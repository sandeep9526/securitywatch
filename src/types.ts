import type { Request, Response, NextFunction } from "express";

export interface DetectionResult {
  triggered: boolean;
  score: number;
  rule: string;
  reason: string;
}

export type Sensitivity = "low" | "medium" | "high" | "critical";
export type SecurityAction = "allow" | "warn" | "throttle" | "block";

export interface Thresholds {
  warn: number;
  throttle: number;
  block: number;
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  routes?: Record<string, number>;
}

export interface BruteForceConfig {
  maxAttempts: number;
  windowMs: number;
  blockDurationMs: number;
  authRoutes?: string[];
}

export interface AlertConfig {
  console?: boolean;
  slackWebhookUrl?: string;
}

export interface SecurityConfig {
  sqlInjection?: boolean;
  xss?: boolean;
  bruteForce?: boolean | BruteForceConfig;
  rateLimit?: boolean | RateLimitConfig;
  suspiciousBehavior?: boolean;
  payloadAnomaly?: boolean;
  ipReputation?: boolean;
  alerts?: AlertConfig;
  routeSensitivity?: Record<string, Sensitivity>;
  whitelist?: string[];
  thresholds?: Partial<Thresholds>;
  onBlock?: (req: Request, info: ThreatInfo) => void;
  onWarn?: (req: Request, info: ThreatInfo) => void;
}

export interface ThreatInfo {
  action: SecurityAction;
  totalScore: number;
  ip: string;
  path: string;
  method: string;
  results: DetectionResult[];
  timestamp: Date;
}

export interface StoreEntry<T = unknown> {
  value: T;
  expiresAt: number;
}

export interface Store {
  get<T = unknown>(key: string): T | undefined;
  set<T = unknown>(key: string, value: T, ttlMs: number): void;
  increment(key: string, ttlMs: number): number;
  delete(key: string): void;
}