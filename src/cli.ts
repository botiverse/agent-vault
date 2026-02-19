#!/usr/bin/env node

import { Command } from "commander";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  vaultExists,
  initVault,
  requireVault,
  setSecret,
  getSecretValue,
  getSecretMeta,
  hasSecret,
  listSecrets,
  removeSecret,
  getAllSecretValues,
} from "./vault.js";
import { redact, restore } from "./redact.js";
import { requireTTY, promptSecret, confirm } from "./tty.js";

const program = new Command();

program
  .name("agent-vault")
  .description("Secure secret management for AI agent config files")
  .version("0.1.0");

// ──────────────────────────────────────────────
// SAFE COMMANDS (agent + human)
// ──────────────────────────────────────────────

program
  .command("read")
  .description("Read a file with secrets redacted (safe for agents)")
  .argument("<file>", "File to read")
  .action((file: string) => {
    const filePath = resolve(file);
    if (!existsSync(filePath)) {
      console.error(`✗ File not found: ${file}`);
      process.exit(1);
    }

    const secretValues = vaultExists() ? getAllSecretValues() : new Map<string, string>();
    const raw = readFileSync(filePath, "utf-8");
    const redacted = redact(raw, secretValues);

    // Output in cat -n format
    const lines = redacted.split("\n");
    // If file ends with newline, last element is empty — don't number it
    const hasTrailingNewline = raw.endsWith("\n") && lines[lines.length - 1] === "";
    const outputLines = hasTrailingNewline ? lines.slice(0, -1) : lines;

    const width = String(outputLines.length).length;
    for (let i = 0; i < outputLines.length; i++) {
      const num = String(i + 1).padStart(Math.max(width, 6));
      console.log(`${num}\t${outputLines[i]}`);
    }
  });

program
  .command("write")
  .description("Write a file, replacing <agent-vault:key> placeholders with real values (safe for agents)")
  .argument("<file>", "File to write")
  .option("--content <content>", "File content with <agent-vault:key> placeholders")
  .action((file: string, opts: { content?: string }) => {
    const filePath = resolve(file);
    let content: string;

    if (opts.content !== undefined) {
      content = opts.content;
    } else if (!process.stdin.isTTY) {
      // Read from stdin
      content = readFileSync(0, "utf-8");
    } else {
      console.error("✗ Provide content via --content flag or stdin");
      process.exit(1);
    }

    requireVault();

    const result = restore(content, (key) => getSecretValue(key));

    if (result.missing.length > 0) {
      console.error(`✗ Error: Secret "${result.missing[0]}" not found in vault`);
      console.error(`  To add it, the user should run: agent-vault set ${result.missing[0]}`);
      if (result.missing.length > 1) {
        for (const key of result.missing.slice(1)) {
          console.error(`  Also missing: "${key}" → agent-vault set ${key}`);
        }
      }
      process.exit(1);
    }

    writeFileSync(filePath, result.content, { mode: 0o644 });
    const count = result.restored.length;
    console.log(`✓ Written ${file} (${count} secret${count !== 1 ? "s" : ""} restored)`);
  });

program
  .command("has")
  .description("Check if secrets exist in the vault (safe for agents)")
  .argument("<keys...>", "Secret key name(s) to check")
  .option("--json", "Output as JSON")
  .action((keys: string[], opts: { json?: boolean }) => {
    if (opts.json) {
      const result: Record<string, boolean> = {};
      for (const key of keys) {
        result[key] = vaultExists() ? hasSecret(key) : false;
      }
      console.log(JSON.stringify(result));
      process.exit(Object.values(result).every(Boolean) ? 0 : 1);
    }

    if (keys.length === 1) {
      const exists = vaultExists() ? hasSecret(keys[0]) : false;
      console.log(String(exists));
      process.exit(exists ? 0 : 1);
    }

    let allExist = true;
    for (const key of keys) {
      const exists = vaultExists() ? hasSecret(key) : false;
      console.log(`${key}: ${exists}`);
      if (!exists) allExist = false;
    }
    process.exit(allExist ? 0 : 1);
  });

program
  .command("list")
  .description("List all stored secret key names (safe for agents)")
  .option("--json", "Output as JSON")
  .action((opts: { json?: boolean }) => {
    if (!vaultExists()) {
      if (opts.json) {
        console.log(JSON.stringify({ keys: [] }));
      }
      return;
    }

    const secrets = listSecrets();

    if (opts.json) {
      console.log(JSON.stringify({ keys: secrets }, null, 2));
      return;
    }

    for (const s of secrets) {
      console.log(s.key);
    }
  });

// ──────────────────────────────────────────────
// SENSITIVE COMMANDS (human only, TTY required)
// ──────────────────────────────────────────────

program
  .command("set")
  .description("Store a secret value (interactive, human only)")
  .argument("<key>", "Secret key name (lowercase alphanumeric + hyphens)")
  .option("--desc <description>", "Description of this secret")
  .option("--from-env <var>", "Read value from environment variable")
  .option("--stdin", "Read value from stdin pipe")
  .action(async (key: string, opts: { desc?: string; fromEnv?: string; stdin?: boolean }) => {
    // Validate key format
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(key)) {
      console.error("✗ Invalid key format. Use lowercase alphanumeric + hyphens (e.g. my-api-key)");
      process.exit(1);
    }

    // Check if key already exists (used across all modes)
    const alreadyExists = vaultExists() && hasSecret(key);
    const existingMeta = alreadyExists ? getSecretMeta(key) : null;

    let value: string;

    if (opts.fromEnv) {
      value = process.env[opts.fromEnv] ?? "";
      if (!value) {
        console.error(`✗ Environment variable $${opts.fromEnv} is not set or empty`);
        process.exit(1);
      }
      if (alreadyExists) {
        process.stderr.write(`⚠ Overwriting "${key}" (was ${existingMeta?.length} chars)\n`);
      }
    } else if (opts.stdin) {
      value = readFileSync(0, "utf-8").trim();
      if (!value) {
        console.error("✗ No input received from stdin");
        process.exit(1);
      }
      if (alreadyExists) {
        process.stderr.write(`⚠ Overwriting "${key}" (was ${existingMeta?.length} chars)\n`);
      }
    } else {
      // Interactive mode — requires TTY
      requireTTY("agent-vault set");

      if (opts.desc) {
        process.stderr.write(`${opts.desc}\n`);
      }

      // Warn and confirm if key already exists
      if (alreadyExists) {
        const desc = existingMeta?.desc ? ` (${existingMeta.desc})` : "";
        process.stderr.write(`⚠ "${key}"${desc} already exists (${existingMeta?.length} chars, set ${existingMeta?.createdAt})\n`);
        const yes = await confirm("Overwrite?");
        if (!yes) {
          console.log("Cancelled");
          return;
        }
      }

      try {
        value = await promptSecret(`Enter value for "${key}": `);
      } catch {
        console.error("\n✗ Cancelled");
        process.exit(1);
      }

      if (!value) {
        console.error("✗ Empty value, nothing saved");
        process.exit(1);
      }
    }

    // Auto-init vault if needed
    if (!vaultExists()) {
      initVault();
      process.stderr.write("✓ Initialized vault at ~/.agent-vault/\n");
    }

    setSecret(key, value, opts.desc);

    if (opts.fromEnv) {
      console.log(`✓ Saved "${key}" (from $${opts.fromEnv})`);
    } else {
      console.log(`✓ Saved "${key}"`);
    }
  });

program
  .command("get")
  .description("View secret metadata or value (human only)")
  .argument("<key>", "Secret key name")
  .option("--reveal", "Show the actual secret value (requires TTY)")
  .action((key: string, opts: { reveal?: boolean }) => {
    requireTTY("agent-vault get");
    requireVault();

    if (opts.reveal) {
      // Double check: --reveal must also be on a TTY stdout
      if (!process.stdout.isTTY) {
        console.error("✗ --reveal requires an interactive terminal (TTY)");
        console.error("  Cannot pipe or redirect secret values.");
        process.exit(1);
      }

      const value = getSecretValue(key);
      if (value === null) {
        console.error(`✗ Secret "${key}" not found`);
        process.exit(1);
      }
      console.log(value);
      return;
    }

    // Metadata only
    const meta = getSecretMeta(key);
    if (!meta) {
      console.error(`✗ Secret "${key}" not found`);
      process.exit(1);
    }

    console.log(`Key:      ${key}`);
    if (meta.desc) console.log(`Desc:     ${meta.desc}`);
    console.log(`Set at:   ${meta.createdAt}`);
    console.log(`Length:   ${meta.length} chars`);
  });

program
  .command("rm")
  .description("Remove a secret from the vault (human only)")
  .argument("<key>", "Secret key name to remove")
  .action(async (key: string) => {
    requireTTY("agent-vault rm");
    requireVault();

    if (!hasSecret(key)) {
      console.error(`✗ Secret "${key}" not found`);
      process.exit(1);
    }

    const yes = await confirm(`Remove "${key}"?`);
    if (!yes) {
      console.log("Cancelled");
      return;
    }

    removeSecret(key);
    console.log(`✓ Removed "${key}"`);
  });

program
  .command("import")
  .description("Import secrets from a .env file (human only)")
  .argument("<file>", ".env file to import")
  .option("--min-length <n>", "Minimum value length to import", "8")
  .action(async (file: string, opts: { minLength: string }) => {
    requireTTY("agent-vault import");

    const filePath = resolve(file);
    if (!existsSync(filePath)) {
      console.error(`✗ File not found: ${file}`);
      process.exit(1);
    }

    const minLength = parseInt(opts.minLength, 10);
    const content = readFileSync(filePath, "utf-8");
    const lines = content.split("\n");

    // Common values to skip
    const COMMON_VALUES = new Set([
      "true", "false", "null", "undefined", "localhost", "0.0.0.0",
      "127.0.0.1", "development", "production", "staging", "test",
    ]);

    interface ImportCandidate {
      envKey: string;
      vaultKey: string;
      value: string;
      skip?: string;
    }

    const candidates: ImportCandidate[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
      if (!match) continue;

      const [, envKey, rawValue] = match;
      const value = rawValue.replace(/^["']|["']$/g, "").trim();

      // Convert SCREAMING_SNAKE to kebab-case
      const vaultKey = envKey.toLowerCase().replace(/_/g, "-");

      if (value.length < minLength) {
        candidates.push({ envKey, vaultKey, value, skip: `too short (${value.length} chars)` });
      } else if (COMMON_VALUES.has(value.toLowerCase())) {
        candidates.push({ envKey, vaultKey, value, skip: `common value` });
      } else {
        candidates.push({ envKey, vaultKey, value });
      }
    }

    if (candidates.length === 0) {
      console.log("No entries found in file");
      return;
    }

    // Display preview
    const toImport = candidates.filter((c) => !c.skip);
    const toSkip = candidates.filter((c) => c.skip);

    console.log(`Found ${candidates.length} entries:\n`);

    const maxEnvKeyLen = Math.max(...candidates.map((c) => c.envKey.length));
    for (const c of toImport) {
      const existing = vaultExists() && hasSecret(c.vaultKey) ? " (overwrite)" : "";
      console.log(`  ${c.envKey.padEnd(maxEnvKeyLen)} → ${c.vaultKey}${existing}`);
    }
    for (const c of toSkip) {
      console.log(`  ${c.envKey.padEnd(maxEnvKeyLen)} → (skip: ${c.skip})`);
    }

    if (toImport.length === 0) {
      console.log("\nNothing to import (all entries skipped)");
      return;
    }

    console.log();
    const yes = await confirm(`Import ${toImport.length} secret${toImport.length !== 1 ? "s" : ""}?`, true);
    if (!yes) {
      console.log("Cancelled");
      return;
    }

    // Auto-init vault if needed
    if (!vaultExists()) {
      initVault();
      process.stderr.write("✓ Initialized vault at ~/.agent-vault/\n");
    }

    for (const c of toImport) {
      setSecret(c.vaultKey, c.value);
    }

    console.log(`✓ Imported ${toImport.length} secret${toImport.length !== 1 ? "s" : ""}`);
  });

program
  .command("init")
  .description("Initialize a new vault (human only)")
  .action(() => {
    requireTTY("agent-vault init");

    if (vaultExists()) {
      console.log("Vault already exists at ~/.agent-vault/");
      return;
    }

    initVault();
    console.log("✓ Initialized vault at ~/.agent-vault/");
  });

program
  .command("scan")
  .description("Audit a file for secrets (human only)")
  .argument("<file>", "File to scan")
  .option("--json", "Output as JSON")
  .action((file: string, opts: { json?: boolean }) => {
    requireTTY("agent-vault scan");

    const filePath = resolve(file);
    if (!existsSync(filePath)) {
      console.error(`✗ File not found: ${file}`);
      process.exit(1);
    }

    const secretValues = vaultExists() ? getAllSecretValues() : new Map<string, string>();

    const raw = readFileSync(filePath, "utf-8");
    const lines = raw.split("\n");

    interface ScanResult {
      line: number;
      key: string;
      type: "vaulted" | "unvaulted-suspect";
    }

    const results: ScanResult[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for known vault values
      for (const [value, key] of secretValues) {
        if (line.includes(value)) {
          results.push({ line: i + 1, key, type: "vaulted" });
        }
      }
    }

    // Also run the redaction to find unvaulted suspects
    const redacted = redact(raw, secretValues);
    const redactedLines = redacted.split("\n");
    for (let i = 0; i < redactedLines.length; i++) {
      const match = redactedLines[i].match(/<agent-vault:UNVAULTED:sha256:([a-f0-9]{8})>/g);
      if (match) {
        for (const m of match) {
          results.push({ line: i + 1, key: m.replace(/<agent-vault:|>/g, ""), type: "unvaulted-suspect" });
        }
      }
    }

    if (opts.json) {
      console.log(
        JSON.stringify({
          file,
          vaulted: results.filter((r) => r.type === "vaulted"),
          unvaulted_suspects: results.filter((r) => r.type === "unvaulted-suspect"),
        }, null, 2)
      );
      return;
    }

    const vaulted = results.filter((r) => r.type === "vaulted");
    const suspects = results.filter((r) => r.type === "unvaulted-suspect");

    console.log(`Vaulted (${vaulted.length}):`);
    if (vaulted.length === 0) {
      console.log("  (none)");
    } else {
      for (const r of vaulted) {
        console.log(`  line ${r.line}: matches "${r.key}"`);
      }
    }

    console.log(`Unvaulted suspects (${suspects.length}):`);
    if (suspects.length === 0) {
      console.log("  (none)");
    } else {
      for (const r of suspects) {
        console.log(`  line ${r.line}: ${r.key}`);
        console.log(`  → Run: agent-vault set <key-name>`);
      }
    }
  });

program.parse();
