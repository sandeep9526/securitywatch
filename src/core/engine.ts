import type {
  SecurityConfig,
  DetectionResult,
  SecurityAction,
  ThreatInfo,
  Thresholds,
  Sensitivity,
  Store,
  BruteForceConfig,
  RateLimitConfig,
} from "../types";
import {
  detectSQLInjection,
  detectXSS,
  createBruteForceDetector,
  createRateLimiter,
  createSuspiciousBehaviorDetector,
  detectPayloadAnomaly,
} from "./rules";
import { IPScorer } from "./scorer";

const DEFAULT_THRESHOLDS: Thresholds = {
  warn: 5,
  throttle: 10,
  block: 15,
};

const SENSITIVITY_MULTIPLIER: Record<Sensitivity, number> = {
  low: 0.5,
  medium: 1,
  high: 1.5,
  critical: 2,
};

export class DetectionEngine {
  private config: SecurityConfig;
  private thresholds: Thresholds;
  private scorer: IPScorer;
  private store: Store;

  private detectBruteForce: ReturnType<typeof createBruteForceDetector>;
  private detectRateLimit: ReturnType<typeof createRateLimiter>;
  private detectSuspicious: ReturnType<typeof createSuspiciousBehaviorDetector>;

  constructor(config: SecurityConfig, store: Store) {
    this.config = config;
    this.store = store;
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...config.thresholds };
    this.scorer = new IPScorer(store);

    const bfConfig = typeof config.bruteForce === "object" ? config.bruteForce : undefined;
    this.detectBruteForce = createBruteForceDetector(store, bfConfig);

    const rlConfig = typeof config.rateLimit === "object" ? config.rateLimit : undefined;
    this.detectRateLimit = createRateLimiter(store, rlConfig);

    this.detectSuspicious = createSuspiciousBehaviorDetector(store);
  }

  analyze(params: {
    ip: string;
    path: string;
    method: string;
    body?: string;
    query?: string;
    headers?: Record<string, string>;
    statusCode?: number;
  }): ThreatInfo {
    const { ip, path, method, body, query, statusCode } = params;
    const results: DetectionResult[] = [];

    // Combine all input sources for payload scanning
    const inputs = [body, query].filter(Boolean) as string[];
    const combinedInput = inputs.join(" ");

    // Run enabled rules
    if (this.config.sqlInjection !== false) {
      results.push(detectSQLInjection(combinedInput));
    }

    if (this.config.xss !== false) {
      results.push(detectXSS(combinedInput));
    }

    if (this.config.bruteForce !== false) {
      results.push(this.detectBruteForce(ip, path, statusCode));
    }

    if (this.config.rateLimit !== false) {
      results.push(this.detectRateLimit(ip, path));
    }

    if (this.config.suspiciousBehavior !== false) {
      results.push(this.detectSuspicious(ip, path, method));
    }

    if (this.config.payloadAnomaly !== false) {
      results.push(detectPayloadAnomaly(combinedInput));
    }

    // Calculate total score
    let totalScore = results
      .filter((r) => r.triggered)
      .reduce((sum, r) => sum + r.score, 0);

    // Apply route sensitivity multiplier
    const sensitivity = this.getRouteSensitivity(path);
    totalScore = Math.round(totalScore * SENSITIVITY_MULTIPLIER[sensitivity]);

    // Add to IP reputation
    if (totalScore > 0) {
      this.scorer.addScore(ip, totalScore);
    } else {
      // Reward normal behavior
      this.scorer.addScore(ip, -0.5);
    }

    // Factor in IP reputation for final decision
    const ipScore = this.scorer.getScore(ip);
    const effectiveScore = Math.max(totalScore, ipScore > 20 ? totalScore + 5 : totalScore);

    const action = this.decide(effectiveScore);

    return {
      action,
      totalScore: effectiveScore,
      ip,
      path,
      method,
      results: results.filter((r) => r.triggered),
      timestamp: new Date(),
    };
  }

  private decide(score: number): SecurityAction {
    if (score >= this.thresholds.block) return "block";
    if (score >= this.thresholds.throttle) return "throttle";
    if (score >= this.thresholds.warn) return "warn";
    return "allow";
  }

  private getRouteSensitivity(path: string): Sensitivity {
    const map = this.config.routeSensitivity ?? {};
    for (const [route, sensitivity] of Object.entries(map)) {
      if (path.startsWith(route)) return sensitivity;
    }
    return "medium";
  }

  isWhitelisted(ip: string): boolean {
    return this.config.whitelist?.includes(ip) ?? false;
  }

  destroy(): void {
    this.scorer.destroy();
  }
}