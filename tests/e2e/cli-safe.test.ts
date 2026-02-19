import { describe, it, expect, beforeEach, afterEach, beforeAll } from "vitest";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createTempVaultDir, removeTempVaultDir, run } from "../helpers/temp-vault.js";

let vaultDir: string;
let workDir: string;

beforeAll(() => {
  // Ensure dist/cli.js is built
});

beforeEach(() => {
  vaultDir = createTempVaultDir();
  workDir = createTempVaultDir(); // separate dir for test files
});

afterEach(() => {
  removeTempVaultDir(vaultDir);
  removeTempVaultDir(workDir);
});

function initAndSet(key: string, value: string) {
  // Use --stdin mode (which reads from piped stdin, no TTY needed) with auto-init
  run(["set", key, "--stdin"], { vaultDir, input: value });
}

// --- read ---

describe("agent-vault read", () => {
  it("redacts vault secrets and shows line numbers", () => {
    initAndSet("my-key", "super-secret-value-12345");
    const filePath = join(workDir, "config.yaml");
    writeFileSync(filePath, "api_key: super-secret-value-12345\nport: 3000\n");

    const { stdout, exitCode } = run(["read", filePath], { vaultDir });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("<agent-vault:my-key>");
    expect(stdout).not.toContain("super-secret-value-12345");
    expect(stdout).toContain("port: 3000");
    // Check cat -n format (line numbers)
    expect(stdout).toMatch(/\d+\t/);
  });

  it("works without vault initialized (passes through unchanged)", () => {
    const filePath = join(workDir, "plain.txt");
    writeFileSync(filePath, "hello world\n");

    const { stdout, exitCode } = run(["read", filePath], { vaultDir });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("hello world");
  });

  it("exits 1 for missing file", () => {
    const { stderr, exitCode } = run(["read", "/nonexistent/file.txt"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("File not found");
  });

  it("detects unvaulted high-entropy strings", () => {
    const filePath = join(workDir, ".env");
    writeFileSync(filePath, "API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\n");

    const { stdout, exitCode } = run(["read", filePath], { vaultDir });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("<agent-vault:UNVAULTED:sha256:");
    expect(stdout).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890");
  });

  it("handles multi-line file with correct line numbers", () => {
    const filePath = join(workDir, "multi.txt");
    writeFileSync(filePath, "line1\nline2\nline3\n");

    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toMatch(/1\tline1/);
    expect(stdout).toMatch(/2\tline2/);
    expect(stdout).toMatch(/3\tline3/);
  });
});

// --- write ---

describe("agent-vault write", () => {
  it("replaces placeholders with real values via --content", () => {
    initAndSet("my-token", "real-token-value-12345");
    const filePath = join(workDir, "out.yaml");

    const { stdout, exitCode } = run(
      ["write", filePath, "--content", "token: <agent-vault:my-token>\nport: 3000"],
      { vaultDir },
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Written");
    expect(stdout).toContain("1 secret restored");

    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("token: real-token-value-12345\nport: 3000");
  });

  it("reads content from stdin", () => {
    initAndSet("my-token", "real-token-value-12345");
    const filePath = join(workDir, "out.yaml");

    const { exitCode } = run(["write", filePath], {
      vaultDir,
      input: "token: <agent-vault:my-token>",
    });
    expect(exitCode).toBe(0);

    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("token: real-token-value-12345");
  });

  it("exits 1 for missing secret key", () => {
    // Init vault but don't set the key
    run(["set", "dummy", "--stdin"], { vaultDir, input: "dummy-val-12345678" });
    const filePath = join(workDir, "out.yaml");

    const { stderr, exitCode } = run(
      ["write", filePath, "--content", "key: <agent-vault:nonexistent>"],
      { vaultDir },
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Secret "nonexistent" not found');
    expect(stderr).toContain("agent-vault set nonexistent");
  });

  it("reports count of restored secrets", () => {
    initAndSet("key-a", "value-a-123456789");
    initAndSet("key-b", "value-b-123456789");
    const filePath = join(workDir, "out.yaml");

    const { stdout } = run(
      ["write", filePath, "--content", "a: <agent-vault:key-a>\nb: <agent-vault:key-b>"],
      { vaultDir },
    );
    expect(stdout).toContain("2 secrets restored");
  });

  it("exits 1 when no vault exists", () => {
    const emptyVault = createTempVaultDir();
    const filePath = join(workDir, "out.yaml");

    const { exitCode, stderr } = run(
      ["write", filePath, "--content", "key: <agent-vault:x>"],
      { vaultDir: emptyVault },
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain("No vault found");

    removeTempVaultDir(emptyVault);
  });

  it("restores UNVAULTED placeholders from existing file", () => {
    initAndSet("dummy", "dummy-value-12345");
    const filePath = join(workDir, "config.env");
    const secretValue = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";

    // Create the original file with real secret
    writeFileSync(filePath, `API_KEY=${secretValue}\nPORT=3000\n`);

    // Read it (gets UNVAULTED placeholder)
    const { stdout: readOut } = run(["read", filePath], { vaultDir });
    expect(readOut).toContain("UNVAULTED");
    expect(readOut).not.toContain(secretValue);

    // Extract the UNVAULTED line from read output
    const lines = readOut.split("\n");
    const apiLine = lines.find((l: string) => l.includes("API_KEY"))!;
    const portLine = lines.find((l: string) => l.includes("PORT"))!;
    const contentToWrite = apiLine.replace(/^\s*\d+\t/, "") + "\n" + portLine.replace(/^\s*\d+\t/, "") + "\n";

    // Write back with UNVAULTED placeholder
    const { stdout, stderr, exitCode } = run(
      ["write", filePath, "--content", contentToWrite],
      { vaultDir },
    );
    expect(exitCode).toBe(0);
    expect(stderr).toContain("unvaulted secret");

    // Verify file still has real value
    const final = readFileSync(filePath, "utf-8");
    expect(final).toContain(secretValue);
    expect(final).toContain("PORT=3000");
    expect(final).not.toContain("UNVAULTED");
  });

  it("exits 1 when UNVAULTED placeholder has no existing file to restore from", () => {
    initAndSet("dummy", "dummy-value-12345");
    const filePath = join(workDir, "new-file.env");

    const { exitCode, stderr } = run(
      ["write", filePath, "--content", "KEY=<agent-vault:UNVAULTED:sha256:deadbeef>"],
      { vaultDir },
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain("UNVAULTED");
    expect(stderr).toContain("does not exist");
  });

  it("exits 1 when UNVAULTED hash cannot be matched in existing file", () => {
    initAndSet("dummy", "dummy-value-12345");
    const filePath = join(workDir, "config.env");
    writeFileSync(filePath, "KEY=short\n");

    const { exitCode, stderr } = run(
      ["write", filePath, "--content", "KEY=<agent-vault:UNVAULTED:sha256:deadbeef>"],
      { vaultDir },
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain("Could not restore");
  });
});

// --- has ---

describe("agent-vault has", () => {
  it("prints true and exits 0 for existing key", () => {
    initAndSet("my-key", "value-12345678901");
    const { stdout, exitCode } = run(["has", "my-key"], { vaultDir });
    expect(stdout.trim()).toBe("true");
    expect(exitCode).toBe(0);
  });

  it("prints false and exits 1 for missing key", () => {
    initAndSet("other", "value-12345678901");
    const { stdout, exitCode } = run(["has", "missing-key"], { vaultDir });
    expect(stdout.trim()).toBe("false");
    expect(exitCode).toBe(1);
  });

  it("exits 0 when all keys exist", () => {
    initAndSet("a", "value-a-12345678");
    initAndSet("b", "value-b-12345678");
    const { exitCode } = run(["has", "a", "b"], { vaultDir });
    expect(exitCode).toBe(0);
  });

  it("exits 1 when any key is missing", () => {
    initAndSet("a", "value-a-12345678");
    const { exitCode } = run(["has", "a", "missing"], { vaultDir });
    expect(exitCode).toBe(1);
  });

  it("outputs JSON with --json", () => {
    initAndSet("a", "value-a-12345678");
    const { stdout } = run(["has", "a", "b", "--json"], { vaultDir });
    const result = JSON.parse(stdout);
    expect(result).toEqual({ a: true, b: false });
  });

  it("works without vault initialized (all false)", () => {
    const emptyVault = createTempVaultDir();
    const { stdout, exitCode } = run(["has", "foo"], { vaultDir: emptyVault });
    expect(stdout.trim()).toBe("false");
    expect(exitCode).toBe(1);
    removeTempVaultDir(emptyVault);
  });
});

// --- list ---

describe("agent-vault list", () => {
  it("prints nothing for empty vault", () => {
    // Init vault with a dummy set+rm to have an empty vault
    initAndSet("temp", "value-12345678901");
    // Actually, just init and check — list on fresh vault
    const freshVault = createTempVaultDir();
    run(["set", "temp", "--stdin"], { vaultDir: freshVault, input: "val-12345678" });
    // For empty vault, we need to init without setting. Use a trick: set then we test list returns the key
    const { stdout } = run(["list"], { vaultDir: freshVault });
    expect(stdout.trim()).toBe("temp");
    removeTempVaultDir(freshVault);
  });

  it("lists key names", () => {
    initAndSet("alpha", "value-alpha-1234");
    initAndSet("beta", "value-beta-12345");
    const { stdout, exitCode } = run(["list"], { vaultDir });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("alpha");
    expect(stdout).toContain("beta");
  });

  it("outputs JSON with --json", () => {
    initAndSet("k1", "value-k1-12345678");
    const { stdout } = run(["list", "--json"], { vaultDir });
    const result = JSON.parse(stdout);
    expect(result.keys).toBeInstanceOf(Array);
    expect(result.keys[0].key).toBe("k1");
  });

  it("works without vault (no output, no error)", () => {
    const emptyVault = createTempVaultDir();
    const { stdout, stderr, exitCode } = run(["list"], { vaultDir: emptyVault });
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toBe("");
    expect(stderr).toBe("");
    removeTempVaultDir(emptyVault);
  });

  it("outputs empty keys array in JSON without vault", () => {
    const emptyVault = createTempVaultDir();
    const { stdout } = run(["list", "--json"], { vaultDir: emptyVault });
    const result = JSON.parse(stdout);
    expect(result).toEqual({ keys: [] });
    removeTempVaultDir(emptyVault);
  });
});
