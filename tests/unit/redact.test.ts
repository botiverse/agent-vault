import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { redact, restore, restoreUnvaulted, extractPlaceholders } from "../../src/redact.js";

function sha256Prefix(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 8);
}

// --- redact() Phase 1: known vault values ---

describe("redact — Phase 1: known values", () => {
  it("replaces a known vault value with placeholder", () => {
    const map = new Map([["sk-proj-abc123def456ghi789", "openai-key"]]);
    const result = redact("api_key: sk-proj-abc123def456ghi789", map);
    expect(result).toBe("api_key: <agent-vault:openai-key>");
  });

  it("replaces multiple occurrences of the same value", () => {
    const map = new Map([["secret-value-12345678", "my-key"]]);
    const input = "a: secret-value-12345678\nb: secret-value-12345678\nc: secret-value-12345678";
    const result = redact(input, map);
    expect(result).toBe("a: <agent-vault:my-key>\nb: <agent-vault:my-key>\nc: <agent-vault:my-key>");
  });

  it("replaces longest match first to avoid partial matches", () => {
    const map = new Map([
      ["abcdefgh12345678", "short-key"],
      ["abcdefgh1234567890", "long-key"],
    ]);
    const result = redact("val: abcdefgh1234567890", map);
    expect(result).toBe("val: <agent-vault:long-key>");
  });

  it("skips values shorter than 8 chars", () => {
    const map = new Map([["short", "k"]]);
    const result = redact("val: short", map);
    expect(result).toBe("val: short");
  });

  it("handles regex special chars in values (uses split/join)", () => {
    const value = "a]b[c{d}e.f*g+h(i)j";
    const map = new Map([[value, "special-key"]]);
    const result = redact(`token: ${value}`, map);
    expect(result).toBe("token: <agent-vault:special-key>");
  });

  it("returns content unchanged with empty map", () => {
    const map = new Map<string, string>();
    const result = redact("just plain text\nno secrets here", map);
    expect(result).toBe("just plain text\nno secrets here");
  });

  it("returns empty string for empty content", () => {
    const map = new Map([["secret12345678", "k"]]);
    expect(redact("", map)).toBe("");
  });

  it("replaces multiple different values", () => {
    const map = new Map([
      ["secret-aaaa-bbbb", "key-a"],
      ["secret-cccc-dddd", "key-b"],
    ]);
    const result = redact("a: secret-aaaa-bbbb\nb: secret-cccc-dddd", map);
    expect(result).toBe("a: <agent-vault:key-a>\nb: <agent-vault:key-b>");
  });
});

// --- redact() Phase 2: entropy-based detection ---

describe("redact — Phase 2: unvaulted high-entropy detection", () => {
  const emptyMap = new Map<string, string>();

  it("detects sk- prefixed token not in vault", () => {
    const token = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    const result = redact(`API_KEY=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
    expect(result).not.toContain(token);
  });

  it("detects ghp_ GitHub token", () => {
    const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    const result = redact(`GITHUB_TOKEN=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("detects xoxb- Slack token", () => {
    const token = "xoxb-1234567890-abcdefghijklmnop";
    const result = redact(`SLACK_TOKEN=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("detects AKIA AWS key", () => {
    const token = "AKIAIOSFODNN7EXAMPLE1";
    const result = redact(`AWS_KEY=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("detects JWT token", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const result = redact(`TOKEN=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("detects high-entropy string >= 16 chars", () => {
    const token = "aB3dE5gH7jK9mN1pR3tU5w";
    const result = redact(`SECRET=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("does NOT flag low-entropy long string", () => {
    const result = redact("PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag strings < 12 chars", () => {
    const result = redact("SHORT=abcde12345", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("skips comment lines with #", () => {
    const result = redact("# API_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("skips comment lines with //", () => {
    const result = redact("// token=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("handles .env format KEY=VALUE", () => {
    const token = "sk-proj-testkey1234567890abcdef";
    const result = redact(`OPENAI_KEY=${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("handles YAML format key: value", () => {
    const token = "sk-proj-testkey1234567890abcdef";
    const result = redact(`api_key: ${token}`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("handles JSON format \"key\": \"value\"", () => {
    const token = "sk-proj-testkey1234567890abcdef";
    const result = redact(`"api_key": "${token}"`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("skips lines that already contain <agent-vault: placeholder", () => {
    const line = "api_key: <agent-vault:my-key>";
    const result = redact(line, emptyMap);
    expect(result).toBe(line);
  });

  it("UNVAULTED placeholder contains correct sha256 prefix", () => {
    const token = "sk-proj-testkey1234567890abcdef";
    const expected = sha256Prefix(token);
    const result = redact(`KEY=${token}`, emptyMap);
    expect(result).toContain(`<agent-vault:UNVAULTED:sha256:${expected}>`);
  });

  it("does not flag all-same-char string (zero entropy)", () => {
    const result = redact("KEY=aaaaaaaaaaaaaaaaaaaaaa", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  // --- False positive prevention: structured values ---

  it("does NOT flag array values (TOML/JSON style)", () => {
    const result = redact('capabilities = ["image_in", "video_in", "thinking"]', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag object/dict values", () => {
    const result = redact('config = {"mode": "production", "debug": false}', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag URL values", () => {
    const result = redact("base_url = https://api.example-service.com/v1/chat", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag domain-like values", () => {
    const result = redact("host = my-service.us-east-1.amazonaws.com", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag file path values", () => {
    const result = redact("data_dir = /var/lib/myapp/data/storage", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag relative path values", () => {
    const result = redact("config_path = ./configs/production/app.toml", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag home-relative path values", () => {
    const result = redact("config_path = ~/Projects/myapp/config.json", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  // --- False positive prevention: word-like segments ---

  it("does NOT flag hyphenated word values (kimi-for-coding)", () => {
    const result = redact('model = "kimi-for-coding"', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag namespaced values (managed:kimi-code)", () => {
    const result = redact('provider = "managed:kimi-code"', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag underscore-separated words (moonshot_search)", () => {
    const result = redact("service_name = moonshot_search_engine", emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does NOT flag slash-separated word paths (oauth/kimi-code)", () => {
    const result = redact('key = "oauth/kimi-code"', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("does flag mixed alpha-digit segments (random password)", () => {
    const result = redact("PASSWORD=sd87adf79uojf", emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("does flag alternating case+digit segments", () => {
    const result = redact("TOKEN=aB3dE5gH7jK9mN", emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("does flag pure-lowercase random strings (bad bigrams)", () => {
    const result = redact("PASSWORD=xqzmjvftpkwlrn", emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("does NOT flag English-like lowercase words", () => {
    const result = redact('provider = "managed-authentication"', emptyMap);
    expect(result).not.toContain("UNVAULTED");
  });

  it("flags value when any segment has mixed char classes", () => {
    // "correct" and "horse" are word-like, but "Xk9m2Qr5" is not
    const result = redact("KEY=correct-horse-Xk9m2Qr5", emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });

  it("still flags known patterns inside array values", () => {
    const token = "sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    const result = redact(`tokens = ["${token}"]`, emptyMap);
    expect(result).toContain("<agent-vault:UNVAULTED:sha256:");
  });
});

// --- restore() ---

describe("restore", () => {
  const getter = (key: string) => {
    const secrets: Record<string, string> = {
      "my-key": "real-secret-value",
      "other-key": "other-secret",
    };
    return secrets[key] ?? null;
  };

  it("replaces a single placeholder", () => {
    const result = restore("key: <agent-vault:my-key>", getter);
    expect(result.content).toBe("key: real-secret-value");
    expect(result.restored).toEqual(["my-key"]);
    expect(result.missing).toEqual([]);
  });

  it("replaces multiple different placeholders", () => {
    const result = restore("a: <agent-vault:my-key>\nb: <agent-vault:other-key>", getter);
    expect(result.content).toBe("a: real-secret-value\nb: other-secret");
    expect(result.restored).toEqual(["my-key", "other-key"]);
  });

  it("reports missing keys", () => {
    const result = restore("key: <agent-vault:nonexistent>", getter);
    expect(result.missing).toEqual(["nonexistent"]);
  });

  it("leaves missing placeholders as-is", () => {
    const result = restore("key: <agent-vault:nonexistent>", getter);
    expect(result.content).toBe("key: <agent-vault:nonexistent>");
  });

  it("returns content unchanged when no placeholders", () => {
    const result = restore("just plain text", getter);
    expect(result.content).toBe("just plain text");
    expect(result.restored).toEqual([]);
    expect(result.missing).toEqual([]);
  });

  it("does NOT match invalid key formats (uppercase, underscore)", () => {
    const result = restore("key: <agent-vault:INVALID_KEY>", getter);
    expect(result.content).toBe("key: <agent-vault:INVALID_KEY>");
    expect(result.restored).toEqual([]);
    expect(result.missing).toEqual([]);
  });

  it("handles placeholder at start of content", () => {
    const result = restore("<agent-vault:my-key> is the value", getter);
    expect(result.content).toBe("real-secret-value is the value");
  });

  it("handles placeholder at end of content", () => {
    const result = restore("value is <agent-vault:my-key>", getter);
    expect(result.content).toBe("value is real-secret-value");
  });

  it("handles multiple same placeholders", () => {
    const result = restore("<agent-vault:my-key> and <agent-vault:my-key>", getter);
    expect(result.content).toBe("real-secret-value and real-secret-value");
  });
});

// --- extractPlaceholders() ---

describe("extractPlaceholders", () => {
  it("extracts unique keys from content", () => {
    const content = "a: <agent-vault:key-a>\nb: <agent-vault:key-b>\nc: <agent-vault:key-a>";
    const result = extractPlaceholders(content);
    expect(result).toEqual(["key-a", "key-b"]);
  });

  it("returns empty array for content with no placeholders", () => {
    expect(extractPlaceholders("no placeholders here")).toEqual([]);
  });

  it("does not extract UNVAULTED placeholders (uppercase not matched)", () => {
    const content = "key: <agent-vault:UNVAULTED:sha256:abcd1234>";
    expect(extractPlaceholders(content)).toEqual([]);
  });

  it("extracts single-char keys", () => {
    expect(extractPlaceholders("<agent-vault:a>")).toEqual(["a"]);
  });

  it("extracts keys with hyphens", () => {
    expect(extractPlaceholders("<agent-vault:my-api-key>")).toEqual(["my-api-key"]);
  });

  it("does not match keys starting with hyphen", () => {
    expect(extractPlaceholders("<agent-vault:-bad>")).toEqual([]);
  });

  it("does not match keys ending with hyphen", () => {
    expect(extractPlaceholders("<agent-vault:bad->")).toEqual([]);
  });
});

// --- restoreUnvaulted ---

describe("restoreUnvaulted", () => {
  const secretValue = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
  const hash = sha256Prefix(secretValue);

  it("restores UNVAULTED placeholder from existing file content", () => {
    const content = `API_KEY=<agent-vault:UNVAULTED:sha256:${hash}>\nport: 3000`;
    const existing = `API_KEY=${secretValue}\nport: 3000`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toBe(`API_KEY=${secretValue}\nport: 3000`);
    expect(result.restoredCount).toBe(1);
    expect(result.unmatched).toEqual([]);
  });

  it("restores multiple UNVAULTED placeholders", () => {
    const secret2 = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";
    const hash2 = sha256Prefix(secret2);
    const content = `A=<agent-vault:UNVAULTED:sha256:${hash}>\nB=<agent-vault:UNVAULTED:sha256:${hash2}>`;
    const existing = `A=${secretValue}\nB=${secret2}`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toBe(existing);
    expect(result.restoredCount).toBe(2);
  });

  it("reports unmatched hashes when existing file has no match", () => {
    const content = `API_KEY=<agent-vault:UNVAULTED:sha256:deadbeef>`;
    const existing = `API_KEY=short`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toContain("UNVAULTED");
    expect(result.restoredCount).toBe(0);
    expect(result.unmatched).toEqual(["deadbeef"]);
  });

  it("leaves non-UNVAULTED placeholders untouched", () => {
    const content = `A=<agent-vault:my-key>\nB=<agent-vault:UNVAULTED:sha256:${hash}>`;
    const existing = `A=something\nB=${secretValue}`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toContain("<agent-vault:my-key>");
    expect(result.content).toContain(secretValue);
    expect(result.restoredCount).toBe(1);
  });

  it("returns content unchanged when no UNVAULTED placeholders present", () => {
    const content = "port: 3000\nhost: localhost";
    const existing = "port: 8080\nhost: localhost";

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toBe(content);
    expect(result.restoredCount).toBe(0);
    expect(result.unmatched).toEqual([]);
  });

  it("handles YAML-style values in existing file", () => {
    const content = `token: <agent-vault:UNVAULTED:sha256:${hash}>`;
    const existing = `token: ${secretValue}`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toBe(`token: ${secretValue}`);
    expect(result.restoredCount).toBe(1);
  });

  it("handles JSON-style values in existing file", () => {
    const content = `  "api_key": "<agent-vault:UNVAULTED:sha256:${hash}>"`;
    const existing = `  "api_key": "${secretValue}"`;

    const result = restoreUnvaulted(content, existing);
    expect(result.content).toBe(`  "api_key": "${secretValue}"`);
    expect(result.restoredCount).toBe(1);
  });
});
