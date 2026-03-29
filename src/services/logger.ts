import type { ThreatInfo } from "../types.js";

const COLORS: Record<string, string> = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

const ACTION_STYLES: Record<string, { color: string; label: string }> = {
  block: { color: COLORS.red, label: "BLOCK" },
  throttle: { color: COLORS.yellow, label: "THROTTLE" },
  warn: { color: COLORS.cyan, label: "WARN" },
};

export function logThreat(info: ThreatInfo): void {
  const style = ACTION_STYLES[info.action];
  if (!style) return;

  const reasons = info.results.map((r) => r.reason).join(" | ");
  console.log(
    `${style.color}[SecurityWatch ${style.label}]${COLORS.reset} ${info.timestamp.toISOString()} ${info.method} ${info.path} from ${info.ip} (score: ${info.totalScore}) — ${reasons}`
  );
}