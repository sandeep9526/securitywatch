import type { DetectionResult, RateLimitConfig, Store } from "../../types";

const DEFAULTS: RateLimitConfig = {
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100,
  routes: {},
};

export function createRateLimiter(store: Store, config?: Partial<RateLimitConfig>) {
  const opts = { ...DEFAULTS, ...config };

  return function detectRateLimit(ip: string, path: string): DetectionResult {
    // Find route-specific limit
    let maxRequests = opts.maxRequests;
    for (const [route, limit] of Object.entries(opts.routes ?? {})) {
      if (path.startsWith(route)) {
        maxRequests = limit;
        break;
      }
    }

    const key = `rl:${ip}:${path}`;
    const globalKey = `rl:global:${ip}`;

    const routeCount = store.increment(key, opts.windowMs);
    const globalCount = store.increment(globalKey, opts.windowMs);

    // Spike detection: more than 3x normal rate
    if (globalCount > opts.maxRequests * 3) {
      return {
        triggered: true,
        score: 6,
        rule: "rate-limit",
        reason: `Traffic spike: ${globalCount} requests in ${opts.windowMs / 1000}s (${opts.maxRequests * 3} threshold)`,
      };
    }

    if (routeCount > maxRequests) {
      return {
        triggered: true,
        score: 4,
        rule: "rate-limit",
        reason: `Rate limit exceeded: ${routeCount}/${maxRequests} on ${path}`,
      };
    }

    return { triggered: false, score: 0, rule: "rate-limit", reason: "" };
  };
}