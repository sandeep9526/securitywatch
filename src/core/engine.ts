import type {
  SecurityConfig, DetectionResult, SecurityAction,
  ThreatInfo, Thresholds, Sensitivity, Store,
} from "../types.js";
import {
  detectSQLInjection, detectXSS, createBruteForceDetector,
  createRateLimiter, createSuspiciousBehaviorDetector, detectPayloadAnomaly,
} from "./rules/index.js";
import { IPScorer } from "./scorer.js";

const DEFAULT_THRESHOLDS: Thresholds = { warn: 5, throttle: 10, block: 15 };

const SENSITIVITY_MULTIPLIER: Record<Sensitivity, number> = {
  low: 0.5, medium: 1, high: 1.5, critical: 2,
};

export class DetectionEngine {
  private config: SecurityConfig;
  private thresholds: Thresholds;
  private scorer: IPScorer | null;

  private detectBruteForce: ReturnType<typeof createBruteForceDetector>;
  private detectRateLimit: ReturnType<typeof createRateLimiter>;
  private detectSuspicious: ReturnType<typeof createSuspiciousBehaviorDetector>;

  constructor(config: SecurityConfig, store: Store) {
    this.config = config;
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...config.thresholds };
    this.scorer = config.ipReputation !== false ? new IPScorer(store) : null;

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
    headers?: string;
  }): ThreatInfo {
    const { ip, path, method, body, query, headers } = params;
    const results: DetectionResult[] = [];

    const payloadInputs = [body, query].filter(Boolean) as string[];
    const combinedPayload = payloadInputs.join(" ");
    const fullInput = headers ? `${combinedPayload} ${headers}` : combinedPayload;

    if (this.config.sqlInjection !== false) results.push(detectSQLInjection(fullInput));
    if (this.config.xss !== false) results.push(detectXSS(fullInput));
    if (this.config.bruteForce !== false) results.push(this.detectBruteForce(ip, path));
    if (this.config.rateLimit !== false) results.push(this.detectRateLimit(ip, path));
    if (this.config.suspiciousBehavior !== false) results.push(this.detectSuspicious(ip, path, method));
    if (this.config.payloadAnomaly !== false) results.push(detectPayloadAnomaly(combinedPayload));

    let totalScore = results
      .filter((r) => r.triggered)
      .reduce((sum, r) => sum + r.score, 0);

    const sensitivity = this.getRouteSensitivity(path);
    totalScore = Math.round(totalScore * SENSITIVITY_MULTIPLIER[sensitivity]);

    if (this.scorer) {
      this.scorer.addScore(ip, totalScore > 0 ? totalScore : -0.5);
      const ipScore = this.scorer.getScore(ip);
      if (ipScore > 20 && totalScore > 0) totalScore += 5;
    }

    return {
      action: this.decide(totalScore),
      totalScore,
      ip, path, method,
      results: results.filter((r) => r.triggered),
      timestamp: new Date(),
    };
  }

  recordResponse(ip: string, path: string, statusCode: number): void {
    if (this.config.bruteForce === false) return;
    this.detectBruteForce(ip, path, statusCode);
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
    this.scorer?.destroy();
  }
}