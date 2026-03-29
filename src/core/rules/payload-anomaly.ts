import type { DetectionResult } from "../../types";

const MAX_PAYLOAD_LENGTH = 10_000;
const SPECIAL_CHAR_THRESHOLD = 0.3; // 30% special characters

function specialCharRatio(input: string): number {
  if (input.length === 0) return 0;
  const specialChars = input.replace(/[a-zA-Z0-9\s.,;:!?@#$%&*()\-_=+\[\]{}'"\/\\]/g, "");
  return specialChars.length / input.length;
}

export function detectPayloadAnomaly(input: string): DetectionResult {
  let score = 0;
  const matched: string[] = [];

  // Oversized payload
  if (input.length > MAX_PAYLOAD_LENGTH) {
    score += 3;
    matched.push(`oversized payload (${input.length} chars)`);
  }

  // High density of special / non-printable characters
  const ratio = specialCharRatio(input);
  if (ratio > SPECIAL_CHAR_THRESHOLD) {
    score += 4;
    matched.push(`high special-char density (${(ratio * 100).toFixed(0)}%)`);
  }

  // Null byte injection
  if (input.includes("\0") || input.includes("%00")) {
    score += 5;
    matched.push("null byte injection");
  }

  // Extremely nested JSON-like structures (potential DoS)
  const nestingDepth = (input.match(/[{[]/g) || []).length;
  if (nestingDepth > 50) {
    score += 3;
    matched.push(`deeply nested structure (${nestingDepth} levels)`);
  }

  return {
    triggered: score > 0,
    score,
    rule: "payload-anomaly",
    reason: matched.length ? `Payload anomaly: ${matched.join(", ")}` : "",
  };
}