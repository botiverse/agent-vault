import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createTempVaultDir, removeTempVaultDir } from "../helpers/temp-vault.js";

let tempDir: string;

beforeEach(() => {
  tempDir = createTempVaultDir();
  process.env.AGENT_VAULT_DIR = tempDir;
});

afterEach(() => {
  delete process.env.AGENT_VAULT_DIR;
  removeTempVaultDir(tempDir);
});

// Dynamic import to pick up the env var each time
async function loadVault() {
  return await import("../../src/vault.js");
}

describe("getVaultDir", () => {
  it("returns AGENT_VAULT_DIR when env var is set", async () => {
    const { getVaultDir } = await loadVault();
    expect(getVaultDir()).toBe(tempDir);
  });

  it("returns ~/.agent-vault when env var is not set", async () => {
    delete process.env.AGENT_VAULT_DIR;
    const { getVaultDir } = await loadVault();
    expect(getVaultDir()).toBe(join(homedir(), ".agent-vault"));
    // Restore for cleanup
    process.env.AGENT_VAULT_DIR = tempDir;
  });
});

describe("vaultExists", () => {
  it("returns false for empty temp dir", async () => {
    const { vaultExists } = await loadVault();
    expect(vaultExists()).toBe(false);
  });

  it("returns true after initVault", async () => {
    const { initVault, vaultExists } = await loadVault();
    initVault();
    expect(vaultExists()).toBe(true);
  });
});

describe("requireVault", () => {
  it("calls process.exit(1) when vault does not exist", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { requireVault } = await loadVault();

    expect(() => requireVault()).toThrow("exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("No vault found"));

    exitSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it("returns vault dir when vault exists", async () => {
    const { initVault, requireVault } = await loadVault();
    initVault();
    expect(requireVault()).toBe(tempDir);
  });
});

describe("initVault", () => {
  it("creates vault.json and vault.key", async () => {
    const { initVault } = await loadVault();
    initVault();
    expect(existsSync(join(tempDir, "vault.json"))).toBe(true);
    expect(existsSync(join(tempDir, "vault.key"))).toBe(true);
  });

  it("vault.json contains { secrets: {} }", async () => {
    const { initVault } = await loadVault();
    initVault();
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(data).toEqual({ secrets: {} });
  });

  it("vault.key is 64 hex characters (32 bytes)", async () => {
    const { initVault } = await loadVault();
    initVault();
    const key = readFileSync(join(tempDir, "vault.key"), "utf-8").trim();
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("creates vault dir with mode 0o700", async () => {
    const { initVault } = await loadVault();
    initVault();
    const stat = statSync(tempDir);
    expect(stat.mode & 0o777).toBe(0o700);
  });

  it("creates vault.key with mode 0o600", async () => {
    const { initVault } = await loadVault();
    initVault();
    const stat = statSync(join(tempDir, "vault.key"));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it("creates vault.json with mode 0o600", async () => {
    const { initVault } = await loadVault();
    initVault();
    const stat = statSync(join(tempDir, "vault.json"));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it("returns vault dir path", async () => {
    const { initVault } = await loadVault();
    expect(initVault()).toBe(tempDir);
  });

  it("is idempotent — second call does not overwrite key", async () => {
    const { initVault } = await loadVault();
    initVault();
    const key1 = readFileSync(join(tempDir, "vault.key"), "utf-8");
    initVault();
    const key2 = readFileSync(join(tempDir, "vault.key"), "utf-8");
    expect(key1).toBe(key2);
  });
});

describe("setSecret / getSecretValue round-trip", () => {
  it("stores and retrieves a simple string", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("my-key", "hello-world-12345");
    expect(getSecretValue("my-key")).toBe("hello-world-12345");
  });

  it("stores and retrieves special characters", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    const value = "p@$$w0rd!#%^&*()_+\n\t{}[]";
    setSecret("special", value);
    expect(getSecretValue("special")).toBe(value);
  });

  it("stores with description", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("k", "value12345678", "my description");
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(data.secrets.k.desc).toBe("my description");
  });

  it("overwrites an existing key", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("k", "original-value-123");
    setSecret("k", "updated-value-456");
    expect(getSecretValue("k")).toBe("updated-value-456");
  });

  it("returns null for missing key", async () => {
    const { initVault, getSecretValue } = await loadVault();
    initVault();
    expect(getSecretValue("nonexistent")).toBeNull();
  });

  it("per-value IV: same plaintext produces different ciphertext", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("k1", "identical-value-12345");
    setSecret("k2", "identical-value-12345");
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(data.secrets.k1.value).not.toBe(data.secrets.k2.value);
  });

  it("encrypted value format is iv:tag:ciphertext (3 hex segments)", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("k", "test-value-12345678");
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    const parts = data.secrets.k.value.split(":");
    expect(parts).toHaveLength(3);
    for (const part of parts) {
      expect(part).toMatch(/^[0-9a-f]+$/);
    }
    // IV should be 24 hex chars (12 bytes), tag 32 hex chars (16 bytes)
    expect(parts[0]).toHaveLength(24);
    expect(parts[1]).toHaveLength(32);
  });
});

describe("getSecretMeta", () => {
  it("returns null for missing key", async () => {
    const { initVault, getSecretMeta } = await loadVault();
    initVault();
    expect(getSecretMeta("nope")).toBeNull();
  });

  it("returns correct length (plaintext length)", async () => {
    const { initVault, setSecret, getSecretMeta } = await loadVault();
    initVault();
    setSecret("k", "exactly-12ch");
    const meta = getSecretMeta("k");
    expect(meta?.length).toBe(12);
  });

  it("returns desc when set", async () => {
    const { initVault, setSecret, getSecretMeta } = await loadVault();
    initVault();
    setSecret("k", "value12345678", "My description");
    expect(getSecretMeta("k")?.desc).toBe("My description");
  });

  it("returns createdAt as valid ISO date", async () => {
    const { initVault, setSecret, getSecretMeta } = await loadVault();
    initVault();
    setSecret("k", "value12345678");
    const meta = getSecretMeta("k");
    expect(() => new Date(meta!.createdAt)).not.toThrow();
    expect(new Date(meta!.createdAt).getTime()).toBeGreaterThan(0);
  });

  it("does not return the encrypted value field", async () => {
    const { initVault, setSecret, getSecretMeta } = await loadVault();
    initVault();
    setSecret("k", "value12345678");
    const meta = getSecretMeta("k") as Record<string, unknown>;
    expect(meta).not.toHaveProperty("value");
  });
});

describe("hasSecret", () => {
  it("returns false for missing key", async () => {
    const { initVault, hasSecret } = await loadVault();
    initVault();
    expect(hasSecret("nope")).toBe(false);
  });

  it("returns true for existing key", async () => {
    const { initVault, setSecret, hasSecret } = await loadVault();
    initVault();
    setSecret("k", "value12345678");
    expect(hasSecret("k")).toBe(true);
  });
});

describe("listSecrets", () => {
  it("returns empty array for fresh vault", async () => {
    const { initVault, listSecrets } = await loadVault();
    initVault();
    expect(listSecrets()).toEqual([]);
  });

  it("returns all keys with descriptions", async () => {
    const { initVault, setSecret, listSecrets } = await loadVault();
    initVault();
    setSecret("a", "val-a-12345678", "desc a");
    setSecret("b", "val-b-12345678", "desc b");
    const result = listSecrets();
    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ key: "a", desc: "desc a" });
    expect(result).toContainEqual({ key: "b", desc: "desc b" });
  });

  it("keys without description have undefined desc", async () => {
    const { initVault, setSecret, listSecrets } = await loadVault();
    initVault();
    setSecret("k", "value12345678");
    const result = listSecrets();
    expect(result[0].desc).toBeUndefined();
  });
});

describe("removeSecret", () => {
  it("returns true and removes an existing key", async () => {
    const { initVault, setSecret, removeSecret, hasSecret } = await loadVault();
    initVault();
    setSecret("k", "value12345678");
    expect(removeSecret("k")).toBe(true);
    expect(hasSecret("k")).toBe(false);
  });

  it("returns false for missing key", async () => {
    const { initVault, removeSecret } = await loadVault();
    initVault();
    expect(removeSecret("nope")).toBe(false);
  });

  it("does not affect other keys", async () => {
    const { initVault, setSecret, removeSecret, hasSecret } = await loadVault();
    initVault();
    setSecret("a", "value-a-12345678");
    setSecret("b", "value-b-12345678");
    removeSecret("a");
    expect(hasSecret("b")).toBe(true);
  });
});

describe("getAllSecretValues", () => {
  it("returns empty map for fresh vault", async () => {
    const { initVault, getAllSecretValues } = await loadVault();
    initVault();
    expect(getAllSecretValues().size).toBe(0);
  });

  it("maps plaintext values to key names", async () => {
    const { initVault, setSecret, getAllSecretValues } = await loadVault();
    initVault();
    setSecret("k1", "value-one-12345");
    setSecret("k2", "value-two-12345");
    const map = getAllSecretValues();
    expect(map.get("value-one-12345")).toBe("k1");
    expect(map.get("value-two-12345")).toBe("k2");
  });
});

describe("error paths", () => {
  it("loadMasterKey exits when vault.key is missing", async () => {
    const { initVault, getSecretValue } = await loadVault();
    initVault();
    // Delete the key file
    const { unlinkSync } = await import("node:fs");
    unlinkSync(join(tempDir, "vault.key"));

    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("exit");
    });
    vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => getSecretValue("k")).toThrow("exit");
    expect(exitSpy).toHaveBeenCalledWith(1);

    exitSpy.mockRestore();
  });

  it("corrupted vault.json throws", async () => {
    const { initVault, hasSecret } = await loadVault();
    initVault();
    writeFileSync(join(tempDir, "vault.json"), "not json{{{");
    expect(() => hasSecret("k")).toThrow();
  });

  it("tampered ciphertext throws on decrypt", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("k", "test-value-12345678");

    // Tamper with the ciphertext
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    const parts = data.secrets.k.value.split(":");
    // Flip some hex chars in the ciphertext
    parts[2] = parts[2].split("").reverse().join("");
    data.secrets.k.value = parts.join(":");
    writeFileSync(join(tempDir, "vault.json"), JSON.stringify(data));

    expect(() => getSecretValue("k")).toThrow();
  });
});
