import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

// --- Vault location ---

export function getVaultDir(): string {
  return process.env.AGENT_VAULT_DIR || join(homedir(), ".agent-vault");
}

export function vaultExists(): boolean {
  return existsSync(join(getVaultDir(), "vault.json"));
}

export function requireVault(): string {
  if (!vaultExists()) {
    console.error("✗ No vault found. Run: agent-vault init");
    process.exit(1);
  }
  return getVaultDir();
}

// --- Vault initialization ---

export function initVault(): string {
  if (existsSync(join(getVaultDir(), "vault.json"))) {
    return getVaultDir();
  }

  mkdirSync(getVaultDir(), { recursive: true, mode: 0o700 });

  // Generate master key (32 bytes = 256 bits)
  const masterKey = randomBytes(32);
  const keyPath = join(getVaultDir(), "vault.key");
  writeFileSync(keyPath, masterKey.toString("hex"), { mode: 0o600 });

  // Create empty vault
  const vaultPath = join(getVaultDir(), "vault.json");
  writeFileSync(vaultPath, JSON.stringify({ secrets: {} }, null, 2), { mode: 0o600 });

  return getVaultDir();
}

// --- Encryption ---

const ALGO = "aes-256-gcm";

function loadMasterKey(): Buffer {
  const keyPath = join(getVaultDir(), "vault.key");
  if (!existsSync(keyPath)) {
    console.error("✗ Vault key not found. Vault may be corrupted.");
    process.exit(1);
  }
  return Buffer.from(readFileSync(keyPath, "utf-8").trim(), "hex");
}

function encrypt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: iv:tag:ciphertext (all hex)
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

function decrypt(packed: string, key: Buffer): string {
  const [ivHex, tagHex, ctHex] = packed.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const ct = Buffer.from(ctHex, "hex");
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ct).toString("utf8") + decipher.final("utf8");
}

// --- Secret store ---

export interface SecretEntry {
  value: string; // encrypted
  desc?: string;
  createdAt: string;
}

interface VaultData {
  secrets: Record<string, SecretEntry>;
}

function loadVaultData(): VaultData {
  const vaultPath = join(getVaultDir(), "vault.json");
  if (!existsSync(vaultPath)) {
    return { secrets: {} };
  }
  return JSON.parse(readFileSync(vaultPath, "utf-8"));
}

function saveVaultData(data: VaultData): void {
  const vaultPath = join(getVaultDir(), "vault.json");
  writeFileSync(vaultPath, JSON.stringify(data, null, 2), { mode: 0o600 });
}

export function setSecret(key: string, value: string, desc?: string): void {
  const masterKey = loadMasterKey();
  const data = loadVaultData();
  data.secrets[key] = {
    value: encrypt(value, masterKey),
    desc,
    createdAt: new Date().toISOString(),
  };
  saveVaultData(data);
}

export function getSecretValue(key: string): string | null {
  const masterKey = loadMasterKey();
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return null;
  return decrypt(entry.value, masterKey);
}

export function getSecretMeta(key: string): Omit<SecretEntry, "value"> & { length: number } | null {
  const masterKey = loadMasterKey();
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return null;
  const plainValue = decrypt(entry.value, masterKey);
  return {
    desc: entry.desc,
    createdAt: entry.createdAt,
    length: plainValue.length,
  };
}

export function hasSecret(key: string): boolean {
  const data = loadVaultData();
  return key in data.secrets;
}

export function listSecrets(): Array<{ key: string; desc?: string }> {
  const data = loadVaultData();
  return Object.entries(data.secrets).map(([key, entry]) => ({
    key,
    desc: entry.desc,
  }));
}

export function removeSecret(key: string): boolean {
  const data = loadVaultData();
  if (!(key in data.secrets)) return false;
  delete data.secrets[key];
  saveVaultData(data);
  return true;
}

/**
 * Returns a map of plaintext secret values → key names.
 * Used by the redaction engine.
 */
export function getAllSecretValues(): Map<string, string> {
  const masterKey = loadMasterKey();
  const data = loadVaultData();
  const map = new Map<string, string>();
  for (const [key, entry] of Object.entries(data.secrets)) {
    const value = decrypt(entry.value, masterKey);
    map.set(value, key);
  }
  return map;
}
