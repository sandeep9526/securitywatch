import type { DetectionResult } from "../../types";

// Script tags
const SCRIPT_TAG = /<script[\s>]/i;

// Event handler injection
const EVENT_HANDLER = /\bon(error|load|click|mouseover|focus|blur|submit|change|input)\s*=/i;

// javascript: protocol
const JS_PROTOCOL = /javascript\s*:/i;

// iframe / object / embed injection
const DANGEROUS_TAGS = /<(iframe|object|embed|form|base|meta|link|svg|math)[\s>]/i;

// data: URI with script content
const DATA_URI = /data\s*:\s*(text\/html|application\/xhtml)/i;

// Expression / eval patterns
const EVAL_PATTERN = /(eval|Function|setTimeout|setInterval)\s*\(/i;

const rules: Array<{ pattern: RegExp; score: number; label: string }> = [
  { pattern: SCRIPT_TAG, score: 6, label: "script tag" },
  { pattern: EVENT_HANDLER, score: 4, label: "event handler injection" },
  { pattern: JS_PROTOCOL, score: 5, label: "javascript: protocol" },
  { pattern: DANGEROUS_TAGS, score: 4, label: "dangerous HTML tag" },
  { pattern: DATA_URI, score: 4, label: "data URI with HTML" },
  { pattern: EVAL_PATTERN, score: 3, label: "eval/Function pattern" },
];

export function detectXSS(input: string): DetectionResult {
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
    rule: "xss",
    reason: matched.length ? `XSS: ${matched.join(", ")}` : "",
  };
}