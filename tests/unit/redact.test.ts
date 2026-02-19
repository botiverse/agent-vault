import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { redact, restore, extractPlaceholders } from "../../src/redact.js";

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

  it("does NOT flag strings < 16 chars", () => {
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
