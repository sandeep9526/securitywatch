import type { DetectionResult, BruteForceConfig, Store } from "../../types";

const DEFAULTS: BruteForceConfig = {
  maxAttempts: 5,
  windowMs: 5 * 60 * 1000, // 5 minutes
  blockDurationMs: 15 * 60 * 1000, // 15 minutes
  authRoutes: ["/login", "/signin", "/auth", "/api/auth", "/api/login"],
};

export function createBruteForceDetector(store: Store, config?: Partial<BruteForceConfig>) {
  const opts = { ...DEFAULTS, ...config };

  return function detectBruteForce(
    ip: string,
    path: string,
    statusCode?: number
  ): DetectionResult {
    const isAuthRoute = opts.authRoutes!.some(
      (route) => path.toLowerCase().startsWith(route)
    );

    if (!isAuthRoute) {
      return { triggered: false, score: 0, rule: "brute-force", reason: "" };
    }

    const blockKey = `bf:block:${ip}`;
    const attemptKey = `bf:attempts:${ip}`;

    // Check if IP is currently blocked
    if (store.get(blockKey)) {
      return {
        triggered: true,
        score: 10,
        rule: "brute-force",
        reason: "IP is temporarily blocked due to repeated failed login attempts",
      };
    }

    // Track failed attempts (4xx status = failed auth)
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      const attempts = store.increment(attemptKey, opts.windowMs);

      if (attempts >= opts.maxAttempts * 4) {
        // 20+ attempts → block 24 hours
        store.set(blockKey, true, 24 * 60 * 60 * 1000);
        return {
          triggered: true,
          score: 10,
          rule: "brute-force",
          reason: `${attempts} failed login attempts — blocked for 24 hours`,
        };
      }

      if (attempts >= opts.maxAttempts * 2) {
        // 10+ attempts → block configured duration
        store.set(blockKey, true, opts.blockDurationMs);
        return {
          triggered: true,
          score: 8,
          rule: "brute-force",
          reason: `${attempts} failed login attempts — temporarily blocked`,
        };
      }

      if (attempts >= opts.maxAttempts) {
        return {
          triggered: true,
          score: 7,
          rule: "brute-force",
          reason: `${attempts} failed login attempts in ${opts.windowMs / 60000} minutes`,
        };
      }
    }

    return { triggered: false, score: 0, rule: "brute-force", reason: "" };
  };
}