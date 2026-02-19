import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createTempVaultDir, removeTempVaultDir, run } from "../helpers/temp-vault.js";

let vaultDir: string;
let workDir: string;

beforeEach(() => {
  vaultDir = createTempVaultDir();
  workDir = createTempVaultDir();
});

afterEach(() => {
  removeTempVaultDir(vaultDir);
  removeTempVaultDir(workDir);
});

// --- init ---

describe("agent-vault init", () => {
  it("requires TTY", () => {
    // E2E tests run without TTY (piped), so init should fail
    const { exitCode, stderr } = run(["init"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- set ---

describe("agent-vault set", () => {
  it("stores value from --from-env", () => {
    const { exitCode, stdout } = run(["set", "my-key", "--from-env", "TEST_SECRET"], {
      vaultDir,
      env: { TEST_SECRET: "secret-value-12345678" },
    });
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Saved "my-key"');
    expect(stdout).toContain("$TEST_SECRET");

    // Verify it's in the vault
    const { stdout: hasOut } = run(["has", "my-key"], { vaultDir });
    expect(hasOut.trim()).toBe("true");
  });

  it("stores value from --stdin", () => {
    const { exitCode, stdout } = run(["set", "my-key", "--stdin"], {
      vaultDir,
      input: "piped-secret-value-1234",
    });
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Saved "my-key"');
  });

  it("exits 1 for invalid key format", () => {
    const { exitCode, stderr } = run(["set", "INVALID_KEY", "--stdin"], {
      vaultDir,
      input: "value",
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("Invalid key format");
  });

  it("exits 1 when --from-env var is not set", () => {
    const { exitCode, stderr } = run(["set", "my-key", "--from-env", "NONEXISTENT_VAR_12345"], {
      vaultDir,
      env: {},
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("not set or empty");
  });

  it("exits 1 for empty stdin", () => {
    const { exitCode, stderr } = run(["set", "my-key", "--stdin"], {
      vaultDir,
      input: "",
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("No input");
  });

  it("auto-initializes vault on first set", () => {
    expect(existsSync(join(vaultDir, "vault.json"))).toBe(false);
    run(["set", "k", "--stdin"], { vaultDir, input: "val-12345678901234" });
    expect(existsSync(join(vaultDir, "vault.json"))).toBe(true);
    expect(existsSync(join(vaultDir, "vault.key"))).toBe(true);
  });

  it("stores description with --desc", () => {
    run(["set", "my-key", "--desc", "My API key", "--stdin"], {
      vaultDir,
      input: "secret-value-12345678",
    });
    const { stdout } = run(["list", "--json"], { vaultDir });
    const result = JSON.parse(stdout);
    expect(result.keys[0].desc).toBe("My API key");
  });

  it("warns on overwrite with --from-env", () => {
    run(["set", "k", "--stdin"], { vaultDir, input: "original-value-12345" });
    const { stderr } = run(["set", "k", "--from-env", "X"], {
      vaultDir,
      env: { X: "new-value-123456789" },
    });
    expect(stderr).toContain("Overwriting");
  });

  it("warns on overwrite with --stdin", () => {
    run(["set", "k", "--stdin"], { vaultDir, input: "original-value-12345" });
    const { stderr } = run(["set", "k", "--stdin"], {
      vaultDir,
      input: "updated-value-12345",
    });
    expect(stderr).toContain("Overwriting");
  });

  it("interactive set requires TTY", () => {
    // Without --from-env or --stdin, set requires TTY
    const { exitCode, stderr } = run(["set", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- get ---

describe("agent-vault get", () => {
  it("requires TTY", () => {
    run(["set", "k", "--stdin"], { vaultDir, input: "val-12345678901234" });
    const { exitCode, stderr } = run(["get", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("exits 1 for missing vault", () => {
    const emptyVault = createTempVaultDir();
    const { exitCode } = run(["get", "k"], { vaultDir: emptyVault });
    expect(exitCode).toBe(1);
    removeTempVaultDir(emptyVault);
  });
});

// --- rm ---

describe("agent-vault rm", () => {
  it("requires TTY", () => {
    run(["set", "k", "--stdin"], { vaultDir, input: "val-12345678901234" });
    const { exitCode, stderr } = run(["rm", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- import ---

describe("agent-vault import", () => {
  it("requires TTY", () => {
    const envFile = join(workDir, ".env");
    writeFileSync(envFile, "KEY=value-12345678901234\n");
    const { exitCode, stderr } = run(["import", envFile], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("exits 1 for missing file", () => {
    const { exitCode, stderr } = run(["import", "/nonexistent/.env"], { vaultDir });
    expect(exitCode).toBe(1);
    // Either TTY error or file not found — TTY check comes first
    expect(stderr).toContain("TTY");
  });
});

// --- scan ---

describe("agent-vault scan", () => {
  it("requires TTY", () => {
    const filePath = join(workDir, "config.yaml");
    writeFileSync(filePath, "port: 3000\n");
    const { exitCode, stderr } = run(["scan", filePath], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- Integration: set then read round-trip ---

describe("e2e round-trip", () => {
  it("set → write → read preserves secrets correctly", () => {
    // Set a secret
    run(["set", "api-key", "--stdin"], {
      vaultDir,
      input: "sk-proj-myrealsecretkey12345678",
    });

    // Write a file with placeholder
    const filePath = join(workDir, "config.yaml");
    run(
      [
        "write",
        filePath,
        "--content",
        "api_key: <agent-vault:api-key>\nport: 8080",
      ],
      { vaultDir },
    );

    // Verify the file has the real value
    const fileContent = readFileSync(filePath, "utf-8");
    expect(fileContent).toBe("api_key: sk-proj-myrealsecretkey12345678\nport: 8080");

    // Read it back — secret should be redacted
    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toContain("<agent-vault:api-key>");
    expect(stdout).not.toContain("sk-proj-myrealsecretkey12345678");
    expect(stdout).toContain("port: 8080");
  });

  it("multiple secrets in a single file round-trip", () => {
    run(["set", "key-a", "--stdin"], { vaultDir, input: "secret-aaa-12345678901" });
    run(["set", "key-b", "--stdin"], { vaultDir, input: "secret-bbb-12345678901" });

    const filePath = join(workDir, "multi.env");
    run(
      [
        "write",
        filePath,
        "--content",
        "A=<agent-vault:key-a>\nB=<agent-vault:key-b>\nC=plain",
      ],
      { vaultDir },
    );

    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("A=secret-aaa-12345678901\nB=secret-bbb-12345678901\nC=plain");

    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toContain("<agent-vault:key-a>");
    expect(stdout).toContain("<agent-vault:key-b>");
    expect(stdout).toContain("C=plain");
  });
});
