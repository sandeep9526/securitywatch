export { securityWatch } from "./middleware/express";

// Types
export type {
  SecurityConfig,
  ThreatInfo,
  DetectionResult,
  SecurityAction,
  Sensitivity,
  Thresholds,
  RateLimitConfig,
  BruteForceConfig,
  AlertConfig,
  Store,
} from "./types";

// Core (for advanced usage)
export { DetectionEngine } from "./core/engine";
export { IPScorer } from "./core/scorer";
export { MemoryStore } from "./store/memory";

// Individual rules (for custom pipelines)
export { detectSQLInjection } from "./core/rules/sql-injection";
export { detectXSS } from "./core/rules/xss";
export { detectPayloadAnomaly } from "./core/rules/payload-anomaly";
export { createBruteForceDetector } from "./core/rules/brute-force";
export { createRateLimiter } from "./core/rules/rate-limit";
export { createSuspiciousBehaviorDetector } from "./core/rules/suspicious-behavior";