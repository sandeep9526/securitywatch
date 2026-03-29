import type { DetectionResult, RateLimitConfig, Store } from "../../types.js";

const DEFAULTS: RateLimitConfig = {
  windowMs: 60 * 1000,
  maxRequests: 100,
  routes: {},
};

function normalizePath(path: string): string {
  return path
    .split("?")[0]
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "/:id")
    .replace(/\/\d+/g, "/:n");
}

export function createRateLimiter(store: Store, config?: Partial<RateLimitConfig>) {
  const opts = { ...DEFAULTS, ...config };

  return function detectRateLimit(ip: string, path: string): DetectionResult {
    const normalized = normalizePath(path);

    let maxRequests = opts.maxRequests;
    for (const [route, limit] of Object.entries(opts.routes ?? {})) {
      if (normalized.startsWith(route)) {
        maxRequests = limit;
        break;
      }
    }

    const key = `rl:${ip}:${normalized}`;
    const globalKey = `rl:global:${ip}`;

    const routeCount = store.increment(key, opts.windowMs);
    const globalCount = store.increment(globalKey, opts.windowMs);

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
        reason: `Rate limit exceeded: ${routeCount}/${maxRequests} on ${normalized}`,
      };
    }

    return { triggered: false, score: 0, rule: "rate-limit", reason: "" };
  };
}