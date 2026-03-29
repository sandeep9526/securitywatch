import type { DetectionResult } from "../../types.js";

const MAX_INPUT_LENGTH = 20_000;

const SCRIPT_TAG = /<script[\s>]/i;
const EVENT_HANDLER =
  /\bon(error|load|click|mouseover|mouseenter|focus|focusin|blur|submit|change|input|keydown|keyup|pointerover|animationend|transitionend|beforeunload)\s{0,3}=/i;
const JS_PROTOCOL = /javascript\s{0,3}:/i;
const DANGEROUS_TAGS = /<(iframe|object|embed|form|base|meta|link|svg|math)[\s>]/i;
const DATA_URI = /data\s{0,3}:\s{0,3}(text\/html|application\/xhtml)/i;
const EVAL_PATTERN = /\b(eval|Function|setTimeout|setInterval)\s{0,3}\(/i;
const TEMPLATE_INJECTION = /\$\{.{0,100}?\}/;

const rules: ReadonlyArray<{ pattern: RegExp; score: number; label: string }> = [
  { pattern: SCRIPT_TAG, score: 6, label: "script tag" },
  { pattern: EVENT_HANDLER, score: 4, label: "event handler injection" },
  { pattern: JS_PROTOCOL, score: 5, label: "javascript: protocol" },
  { pattern: DANGEROUS_TAGS, score: 4, label: "dangerous HTML tag" },
  { pattern: DATA_URI, score: 4, label: "data URI with HTML" },
  { pattern: EVAL_PATTERN, score: 3, label: "eval/Function pattern" },
  { pattern: TEMPLATE_INJECTION, score: 3, label: "template literal injection" },
];

export function detectXSS(input: string): DetectionResult {
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
    rule: "xss",
    reason: matched.length ? `XSS: ${matched.join(", ")}` : "",
  };
}