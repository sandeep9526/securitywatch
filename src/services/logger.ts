import type { ThreatInfo } from "../types";

const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

export function logThreat(info: ThreatInfo): void {
  const ts = info.timestamp.toISOString();
  const reasons = info.results.map((r) => r.reason).join(" | ");

  if (info.action === "block") {
    console.log(
      `${COLORS.red}[SecurityWatch BLOCK]${COLORS.reset} ${ts} ${info.method} ${info.path} from ${info.ip} (score: ${info.totalScore}) — ${reasons}`
    );
  } else if (info.action === "throttle") {
    console.log(
      `${COLORS.yellow}[SecurityWatch THROTTLE]${COLORS.reset} ${ts} ${info.method} ${info.path} from ${info.ip} (score: ${info.totalScore}) — ${reasons}`
    );
  } else if (info.action === "warn") {
    console.log(
      `${COLORS.cyan}[SecurityWatch WARN]${COLORS.reset} ${ts} ${info.method} ${info.path} from ${info.ip} (score: ${info.totalScore}) — ${reasons}`
    );
  }
}