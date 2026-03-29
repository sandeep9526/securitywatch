import type { DetectionResult } from "../../types";

// Tautology attacks: ' OR 1=1, " OR ""="
const TAUTOLOGY = /('|")\s*OR\s+(['"]?\w+['"]?\s*=\s*['"]?\w+['"]?|1\s*=\s*1)/i;

// UNION-based injection
const UNION_SELECT = /UNION\s+(ALL\s+)?SELECT/i;

// Stacked queries with dangerous keywords
const STACKED_QUERY = /;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|EXEC)\b/i;

// Comment-based bypass (only flag when combined with suspicious keywords)
const COMMENT_WITH_SQL = /(--|\/\*).*(SELECT|DROP|INSERT|DELETE|UPDATE|UNION)/i;

// Hex/char encoding bypass attempts
const ENCODED_INJECTION = /(CHAR|CHR|0x)\s*\(/i;

// SLEEP / BENCHMARK (time-based blind injection)
const TIME_BASED = /(SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP)\s*\(/i;

const rules: Array<{ pattern: RegExp; score: number; label: string }> = [
  { pattern: TAUTOLOGY, score: 5, label: "tautology attack" },
  { pattern: UNION_SELECT, score: 5, label: "UNION SELECT" },
  { pattern: STACKED_QUERY, score: 6, label: "stacked query" },
  { pattern: COMMENT_WITH_SQL, score: 4, label: "comment bypass with SQL keyword" },
  { pattern: ENCODED_INJECTION, score: 4, label: "encoded injection" },
  { pattern: TIME_BASED, score: 5, label: "time-based blind injection" },
];

export function detectSQLInjection(input: string): DetectionResult {
  let score = 0;
  const matched: string[] = [];

  for (const rule of rules) {
    if (rule.pattern.test(input)) {
      score += rule.score;
      matched.push(rule.label);
    }
  }

  return {
    triggered: score > 0,
    score,
    rule: "sql-injection",
    reason: matched.length ? `SQL injection: ${matched.join(", ")}` : "",
  };
}