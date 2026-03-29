import type { DetectionResult } from "../../types.js";

const MAX_PAYLOAD_LENGTH = 10_000;
const SPECIAL_CHAR_THRESHOLD = 0.3;
const MAX_NESTING_DEPTH = 50;

function specialCharRatio(input: string): number {
  if (input.length === 0) return 0;
  const specialChars = input.replace(/[a-zA-Z0-9\s.,;:!?@#$%&*()\-_=+\[\]{}'"\/\\]/g, "");
  return specialChars.length / input.length;
}

function calculateNestingDepth(input: string): number {
  let maxDepth = 0;
  let currentDepth = 0;
  for (const char of input) {
    if (char === "{" || char === "[") {
      currentDepth++;
      if (currentDepth > maxDepth) maxDepth = currentDepth;
    } else if (char === "}" || char === "]") {
      currentDepth = Math.max(0, currentDepth - 1);
    }
  }
  return maxDepth;
}

export function detectPayloadAnomaly(input: string): DetectionResult {
  let score = 0;
  const matched: string[] = [];

  if (input.length > MAX_PAYLOAD_LENGTH) {
    score += 3;
    matched.push(`oversized payload (${input.length} chars)`);
  }

  const ratio = specialCharRatio(input);
  if (ratio > SPECIAL_CHAR_THRESHOLD) {
    score += 4;
    matched.push(`high special-char density (${(ratio * 100).toFixed(0)}%)`);
  }

  if (input.includes("\0") || input.includes("%00")) {
    score += 5;
    matched.push("null byte injection");
  }

  const depth = calculateNestingDepth(input);
  if (depth > MAX_NESTING_DEPTH) {
    score += 3;
    matched.push(`deeply nested structure (depth ${depth})`);
  }

  return {
    triggered: score > 0,
    score,
    rule: "payload-anomaly",
    reason: matched.length ? `Payload anomaly: ${matched.join(", ")}` : "",
  };
}