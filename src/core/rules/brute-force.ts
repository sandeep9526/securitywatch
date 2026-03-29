import type { DetectionResult, BruteForceConfig, Store } from "../../types.js";

const DEFAULTS: BruteForceConfig = {
  maxAttempts: 5,
  windowMs: 5 * 60 * 1000,
  blockDurationMs: 15 * 60 * 1000,
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

    if (store.get(blockKey)) {
      return {
        triggered: true,
        score: 10,
        rule: "brute-force",
        reason: "IP is temporarily blocked due to repeated failed login attempts",
      };
    }

    // Clear counter on successful auth
    if (statusCode !== undefined && statusCode >= 200 && statusCode < 300) {
      store.delete(attemptKey);
      return { triggered: false, score: 0, rule: "brute-force", reason: "" };
    }

    if (statusCode !== undefined && statusCode >= 400 && statusCode < 500) {
      const attempts = store.increment(attemptKey, opts.windowMs);

      if (attempts >= opts.maxAttempts * 4) {
        store.set(blockKey, true, 24 * 60 * 60 * 1000);
        return {
          triggered: true,
          score: 10,
          rule: "brute-force",
          reason: `${attempts} failed login attempts — blocked for 24 hours`,
        };
      }

      if (attempts >= opts.maxAttempts * 2) {
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

    // Pre-request: check existing attempt count
    if (statusCode === undefined) {
      const currentAttempts = store.get<number>(attemptKey) ?? 0;
      if (currentAttempts >= opts.maxAttempts) {
        return {
          triggered: true,
          score: 5,
          rule: "brute-force",
          reason: `${currentAttempts} prior failed login attempts from this IP`,
        };
      }
    }

    return { triggered: false, score: 0, rule: "brute-force", reason: "" };
  };
}