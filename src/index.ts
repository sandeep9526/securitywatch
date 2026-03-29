export { securityWatch } from "./middleware/express.js";

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
  SecurityWatchMiddleware,
} from "./types.js";

// Core (for advanced usage)
export { DetectionEngine } from "./core/engine.js";
export { IPScorer } from "./core/scorer.js";
export { MemoryStore } from "./store/memory.js";

// Individual rules (for custom pipelines)
export { detectSQLInjection } from "./core/rules/sql-injection.js";
export { detectXSS } from "./core/rules/xss.js";
export { detectPayloadAnomaly } from "./core/rules/payload-anomaly.js";
export { createBruteForceDetector } from "./core/rules/brute-force.js";
export { createRateLimiter } from "./core/rules/rate-limit.js";
export { createSuspiciousBehaviorDetector } from "./core/rules/suspicious-behavior.js";
