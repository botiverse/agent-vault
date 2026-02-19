import { mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

export function createTempVaultDir(): string {
  return mkdtempSync(join(tmpdir(), "agent-vault-test-"));
}

export function removeTempVaultDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

const CLI_PATH = resolve(import.meta.dirname, "../../dist/cli.js");

export function run(
  args: string[],
  opts?: {
    env?: Record<string, string>;
    input?: string;
    vaultDir: string;
  },
): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync("node", [CLI_PATH, ...args], {
    env: {
      ...process.env,
      AGENT_VAULT_DIR: opts?.vaultDir,
      ...opts?.env,
    },
    input: opts?.input,
    encoding: "utf-8",
    timeout: 5000,
  });

  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.status ?? 1,
  };
}
