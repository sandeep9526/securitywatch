import type { DetectionResult } from "../../types.js";

const MAX_INPUT_LENGTH = 20_000;

const TAUTOLOGY = /('|")\s{0,5}OR\s{1,5}(1\s*=\s*1|\w{1,20}\s*=\s*\w{1,20})/i;
const UNION_SELECT = /UNION\s{1,10}(ALL\s{1,10})?SELECT\b/i;
const STACKED_QUERY = /;\s{0,5}(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|EXEC)\b/i;
const COMMENT_WITH_SQL = /(--|\/\*).{0,200}?(SELECT|DROP|INSERT|DELETE|UPDATE|UNION)\b/i;
const ENCODED_INJECTION = /(CHAR|CHR|0x)\s{0,3}\(/i;
const TIME_BASED = /(SLEEP|BENCHMARK|WAITFOR\s{1,5}DELAY|PG_SLEEP)\s{0,3}\(/i;
const NOSQL_OPERATOR = /\$\s{0,3}(gt|gte|lt|lte|ne|in|nin|regex|where|exists|or|and)\b/i;
const COMMAND_EXECUTION = /\b(xp_cmdshell|cmd\.exe|EXEC(UTE)?)\b/i;
const SCHEMA_MANIPULATION = /\b(DROP\s{1,5}(TABLE|DATABASE|INDEX|VIEW)|ALTER\s{1,5}TABLE|GRANT\s{1,5}ALL|FLUSH\s{1,5}PRIVILEGES)\b/i;
const MASS_EXPORT = /\b(INTO\s{1,5}(OUT|DUMP)FILE|mysqldump|pg_dump)\b/i;

const rules: ReadonlyArray<{ pattern: RegExp; score: number; label: string }> = [
  { pattern: TAUTOLOGY, score: 5, label: "tautology attack" },
  { pattern: UNION_SELECT, score: 5, label: "UNION SELECT" },
  { pattern: STACKED_QUERY, score: 6, label: "stacked query" },
  { pattern: COMMENT_WITH_SQL, score: 4, label: "comment bypass with SQL keyword" },
  { pattern: ENCODED_INJECTION, score: 4, label: "encoded injection" },
  { pattern: TIME_BASED, score: 5, label: "time-based blind injection" },
  { pattern: NOSQL_OPERATOR, score: 4, label: "NoSQL operator injection" },
  { pattern: COMMAND_EXECUTION, score: 6, label: "OS command execution via SQL" },
  { pattern: SCHEMA_MANIPULATION, score: 6, label: "schema manipulation" },
  { pattern: MASS_EXPORT, score: 5, label: "mass data export" },
];

export function detectSQLInjection(input: string): DetectionResult {
  const safe = input.length > MAX_INPUT_LENGTH ? input.slice(0, MAX_INPUT_LENGTH) : input;
  let score = 0;
  const matched: string[] = [];

  for (const rule of rules) {
    if (rule.pattern.test(safe)) {
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