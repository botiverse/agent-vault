import { createHash } from "node:crypto";

const PLACEHOLDER_RE = /<agent-vault:([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)>/g;
const UNVAULTED_RE = /<agent-vault:UNVAULTED:sha256:[a-f0-9]{8}>/g;

// Minimum length for a secret value to be redacted on read.
// Prevents false positives from short values like "true", "3000", etc.
const MIN_REDACT_LENGTH = 8;

// --- Known secret patterns ---

const SECRET_PATTERNS: RegExp[] = [
  // OpenAI
  /sk-[A-Za-z0-9_-]{20,}/,
  /sk-proj-[A-Za-z0-9_-]{20,}/,
  // Anthropic
  /sk-ant-[A-Za-z0-9_-]{20,}/,
  // GitHub
  /gh[po]_[A-Za-z0-9_]{36,}/,
  /github_pat_[A-Za-z0-9_]{22,}/,
  // Slack
  /xox[bpas]-[A-Za-z0-9-]{10,}/,
  // Stripe
  /sk_live_[A-Za-z0-9]{24,}/,
  /sk_test_[A-Za-z0-9]{24,}/,
  /pk_live_[A-Za-z0-9]{24,}/,
  /pk_test_[A-Za-z0-9]{24,}/,
  // AWS
  /AKIA[0-9A-Z]{16}/,
  // Telegram bot tokens
  /[0-9]{8,10}:[A-Za-z0-9_-]{35}/,
  // Generic long hex strings (40+ chars, like SHA hashes or API keys)
  /[0-9a-f]{40,}/,
  // Generic long base64-like strings (32+ chars)
  /[A-Za-z0-9+/]{32,}={0,2}/,
  // Private key blocks
  /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/,
  // JWT tokens
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9_.-]{20,}/,
];

// --- Shannon entropy ---

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// A string is "high entropy" if it's long enough and has sufficient entropy.
// Typical thresholds: English text ~4.0, random hex ~3.7, random base64 ~5.5
const HIGH_ENTROPY_THRESHOLD = 3.0;
const HIGH_ENTROPY_MIN_LENGTH = 12;

function isHighEntropy(s: string): boolean {
  if (s.length < HIGH_ENTROPY_MIN_LENGTH) return false;
  return shannonEntropy(s) >= HIGH_ENTROPY_THRESHOLD;
}

function matchesSecretPattern(s: string): boolean {
  return SECRET_PATTERNS.some((p) => p.test(s));
}

// --- English bigram analysis ---

// Top ~110 English bigrams by frequency. A segment whose bigram hit rate
// is high is likely a real word; random strings score very low (~17%).
// prettier-ignore
const COMMON_BIGRAMS = new Set([
  "th","he","in","er","an","re","on","en","at","es",
  "ed","te","ti","or","st","ar","nd","to","nt","is",
  "of","it","al","as","ha","ng","co","se","me","de",
  "le","ou","no","ne","ea","ri","ro","li","ra","io",
  "ic","el","la","ve","ta","ce","ma","si","om","ur",
  "ec","il","ge","lo","ch","so","pr","pe","fo","ca",
  "di","be","mo","ag","un","us","wi","hi","sh","ac",
  "ad","ol","ab","mi","im","id","oo","ke","ki","su",
  "po","pa","wa","up","do","fi","ho","da","fe","vi",
  "ow","am","ut","ni","lu","tr","pl","bl","sp","cr",
  "na","ot","ns","ll","ss","wh","ck","gh","ry","ly",
  "ty","ay","ey",
]);

/**
 * Check if a string looks like English/readable text by analyzing its
 * character bigram distribution. Random strings have very few common
 * English bigrams; real words and tech terms (even brand names like
 * "kimi") naturally follow English phonological patterns.
 */
function looksLikeEnglish(seg: string): boolean {
  const s = seg.toLowerCase();
  const n = s.length - 1;
  if (n <= 0) return true;
  let hits = 0;
  for (let i = 0; i < n; i++) {
    if (COMMON_BIGRAMS.has(s.slice(i, i + 2))) hits++;
  }
  return hits / n >= 0.3;
}

// --- Non-secret heuristic ---

/**
 * Heuristic check: does this value look like structured/non-secret content?
 * Used to reduce false positives from entropy-only detection.
 * Pattern-based detection is NOT affected by this check.
 *
 * Approach: split by non-alphanumeric delimiters and check if all segments
 * are "word-like". For pure-letter segments, uses bigram frequency analysis
 * to distinguish real words from random strings.
 */
function looksLikeNonSecret(s: string): boolean {
  // Array or object literals: ["a", "b"], {key: value}
  if (/^\[.*\]$/s.test(s) || /^\{.*\}$/s.test(s)) return true;

  // URLs
  if (/^https?:\/\//i.test(s)) return true;

  // File paths
  if (/^[~.]?\//.test(s)) return true;

  // Word segment check: split by non-alphanumeric chars, then verify
  // each segment looks like a real word (via bigram analysis), an
  // acronym, or a number.
  const segments = s.split(/[^a-zA-Z0-9]+/).filter((seg) => seg.length > 0);
  if (segments.length === 0) return false;
  return segments.every(isWordLikeSegment);
}

/**
 * A segment looks "word-like" if it's a number, an uppercase acronym,
 * or a letter sequence whose bigrams match common English patterns.
 */
function isWordLikeSegment(seg: string): boolean {
  if (seg.length <= 3) return true; // too short to judge
  if (/^[A-Z]+$/.test(seg)) return true; // ACRONYM (HTTP, API, URL)
  if (/^[0-9]+$/.test(seg)) return true; // number
  if (/^[a-zA-Z]+$/.test(seg)) return looksLikeEnglish(seg); // bigram check
  return false; // mixed digits+letters → likely random
}

function sha256Prefix(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 8);
}

// --- Redaction (for `read`) ---

/**
 * Redact known vault secrets and high-entropy unvaulted strings.
 *
 * @param content - The raw file content
 * @param secretValues - Map of plaintext value → vault key name
 * @returns Redacted content
 */
export function redact(content: string, secretValues: Map<string, string>): string {
  let result = content;

  // Phase 1: Replace known vault values (longest first to avoid partial matches)
  const entries = [...secretValues.entries()]
    .filter(([value]) => value.length >= MIN_REDACT_LENGTH)
    .sort((a, b) => b[0].length - a[0].length);

  for (const [value, key] of entries) {
    // Use split+join for global replacement (avoids regex special chars)
    result = result.split(value).join(`<agent-vault:${key}>`);
  }

  // Phase 2: Detect and redact unvaulted high-entropy strings.
  // We tokenize by common delimiters and check each token.
  result = redactUnvaultedTokens(result, secretValues);

  return result;
}

/**
 * Scan for unvaulted high-entropy tokens in content that has already had
 * known values replaced.
 */
function redactUnvaultedTokens(content: string, knownValues: Map<string, string>): string {
  // Split lines, then for each line, look at "value" portions.
  // We target common config formats: KEY=VALUE, key: value, "key": "value"
  const lines = content.split("\n");
  const knownSet = new Set(knownValues.keys());

  return lines
    .map((line) => {
      // Skip lines that already have vault placeholders
      if (line.includes("<agent-vault:")) return line;

      // Try to extract the "value" part from common formats
      const valueCandidates = extractValueCandidates(line);
      let result = line;

      for (const candidate of valueCandidates) {
        const trimmed = candidate.trim().replace(/^["']|["'],?$/g, "");
        if (trimmed.length < HIGH_ENTROPY_MIN_LENGTH) continue;
        if (knownSet.has(trimmed)) continue; // already handled in phase 1

        if (matchesSecretPattern(trimmed) || (isHighEntropy(trimmed) && !looksLikeNonSecret(trimmed))) {
          const hash = sha256Prefix(trimmed);
          result = result.replace(candidate, `<agent-vault:UNVAULTED:sha256:${hash}>`);
        }
      }

      return result;
    })
    .join("\n");
}

function extractValueCandidates(line: string): string[] {
  const candidates: string[] = [];
  const trimmed = line.trim();

  // Skip comment lines
  if (trimmed.startsWith("#") || trimmed.startsWith("//")) return candidates;

  // KEY=VALUE (.env style)
  const envMatch = trimmed.match(/^[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$/);
  if (envMatch) {
    candidates.push(envMatch[1]);
  }

  // key: value (YAML style)
  const yamlMatch = trimmed.match(/^[A-Za-z_][A-Za-z0-9_.-]*\s*:\s+(.+)$/);
  if (yamlMatch) {
    candidates.push(yamlMatch[1]);
  }

  // "key": "value" (JSON style)
  const jsonMatch = trimmed.match(/"[^"]+"\s*:\s*"([^"]+)"/);
  if (jsonMatch) {
    candidates.push(jsonMatch[1]);
  }

  return candidates;
}

// --- Restoration (for `write`) ---

/**
 * Restore vault placeholders with real secret values.
 *
 * @param content - Content with <agent-vault:key> placeholders
 * @param getSecret - Function to look up secret value by key name
 * @returns Object with restored content and list of missing keys
 */
export function restore(
  content: string,
  getSecret: (key: string) => string | null
): { content: string; restored: string[]; missing: string[] } {
  const restored: string[] = [];
  const missing: string[] = [];

  const result = content.replace(PLACEHOLDER_RE, (match, key: string) => {
    const value = getSecret(key);
    if (value === null) {
      missing.push(key);
      return match; // leave placeholder as-is
    }
    restored.push(key);
    return value;
  });

  return { content: result, restored, missing };
}

/**
 * Restore UNVAULTED placeholders by matching sha256 prefixes against
 * high-entropy tokens found in the existing file on disk.
 *
 * @param content - Content with <agent-vault:UNVAULTED:sha256:...> placeholders
 * @param existingContent - The current file content on disk
 * @returns Object with restored content, count of restored tokens, and unmatched hashes
 */
export function restoreUnvaulted(
  content: string,
  existingContent: string,
): { content: string; restoredCount: number; unmatched: string[] } {
  // Build a map: sha256_prefix → original value from existing file
  const hashToValue = new Map<string, string>();
  const existingLines = existingContent.split("\n");

  for (const line of existingLines) {
    const candidates = extractValueCandidates(line);
    for (const candidate of candidates) {
      const trimmed = candidate.trim().replace(/^["']|["'],?$/g, "");
      if (trimmed.length < HIGH_ENTROPY_MIN_LENGTH) continue;
      if (matchesSecretPattern(trimmed) || (isHighEntropy(trimmed) && !looksLikeNonSecret(trimmed))) {
        const hash = sha256Prefix(trimmed);
        hashToValue.set(hash, trimmed);
      }
    }
  }

  let restoredCount = 0;
  const unmatched: string[] = [];

  const result = content.replace(UNVAULTED_RE, (match) => {
    const hash = match.match(/sha256:([a-f0-9]{8})/)?.[1];
    if (!hash) return match;
    const value = hashToValue.get(hash);
    if (value) {
      restoredCount++;
      return value;
    }
    unmatched.push(hash);
    return match;
  });

  return { content: result, restoredCount, unmatched };
}

/**
 * Extract all <agent-vault:key> placeholder references from content.
 */
export function extractPlaceholders(content: string): string[] {
  const keys: string[] = [];
  let match;
  const re = new RegExp(PLACEHOLDER_RE.source, "g");
  while ((match = re.exec(content)) !== null) {
    if (!keys.includes(match[1])) keys.push(match[1]);
  }
  return keys;
}
