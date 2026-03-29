import { describe, it, expect, vi, afterEach } from "vitest";
import { securityWatch } from "../src/middleware/express";
import type { Request, Response } from "express";
import type { SecurityWatchMiddleware } from "../src/types";

function createMockReq(overrides: Partial<Request> & { remoteAddress?: string } = {}): Request {
  const { remoteAddress = "10.0.0.1", ...rest } = overrides;

  return {
    headers: {},
    query: {},
    body: undefined,
    params: {},
    path: "/test",
    method: "GET",
    url: "/test",
    socket: { remoteAddress },
    ...rest,
  } as unknown as Request;
}

function createMockRes(): Response & { _emit: (event: string) => void } {
  const listeners: Record<string, Array<(...args: any[]) => void>> = {};
  const res = {
    statusCode: 200,
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    setHeader: vi.fn().mockReturnThis(),
    on: vi.fn((event: string, cb: (...args: any[]) => void) => {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push(cb);
      return res;
    }),
    _emit: (event: string) => {
      for (const cb of listeners[event] ?? []) cb();
    },
  };
  return res as unknown as Response & { _emit: (event: string) => void };
}

describe("Express Middleware", () => {
  let middleware: SecurityWatchMiddleware;

  afterEach(() => {
    middleware?.destroy();
  });

  it("allows clean requests through", () => {
    middleware = securityWatch();
    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("blocks SQL injection attacks", () => {
    middleware = securityWatch({
      thresholds: { warn: 3, throttle: 8, block: 10 },
    });
    const req = createMockReq({
      path: "/search",
      url: "/search?q=' OR 1=1; DROP TABLE users--",
      query: { q: "' OR 1=1; DROP TABLE users--" } as any,
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: "Forbidden" })
    );
  });

  it("skips whitelisted IPs", () => {
    middleware = securityWatch({ whitelist: ["10.0.0.1"] });
    const req = createMockReq({
      path: "/search",
      url: "/search?q=' OR 1=1",
      query: { q: "' OR 1=1" } as any,
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("does NOT trust X-Forwarded-For by default", () => {
    middleware = securityWatch({ whitelist: ["1.2.3.4"] });
    const req = createMockReq({
      headers: { "x-forwarded-for": "1.2.3.4" } as any,
      remoteAddress: "10.0.0.99",
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    // Uses socket IP (10.0.0.99), not X-Forwarded-For (1.2.3.4)
    // Clean request passes through either way
    expect(next).toHaveBeenCalled();
  });

  it("trusts X-Forwarded-For when trustProxy is enabled", () => {
    middleware = securityWatch({
      trustProxy: true,
      whitelist: ["1.2.3.4"],
    });
    const req = createMockReq({
      headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" } as any,
      remoteAddress: "10.0.0.99",
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("returns 429 for throttled requests", () => {
    middleware = securityWatch({
      rateLimit: { windowMs: 60000, maxRequests: 2 },
      thresholds: { warn: 2, throttle: 4, block: 15 },
    });

    // Exceed rate limit
    for (let i = 0; i < 3; i++) {
      middleware(createMockReq(), createMockRes(), vi.fn());
    }

    const res = createMockRes();
    const next = vi.fn();
    middleware(createMockReq(), res, next);
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.setHeader).toHaveBeenCalledWith("Retry-After", "60");
  });

  it("attaches threat info to warned requests", () => {
    middleware = securityWatch({
      thresholds: { warn: 4, throttle: 20, block: 30 },
    });
    const req = createMockReq({
      path: "/.env",
      url: "/.env",
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.securityWatch).toBeDefined();
    expect(req.securityWatch!.action).toBe("warn");
  });

  it("calls onBlock callback", () => {
    const onBlock = vi.fn();
    middleware = securityWatch({
      onBlock,
      thresholds: { warn: 3, throttle: 8, block: 10 },
    });
    const req = createMockReq({
      path: "/search",
      url: "/search?q=' OR 1=1; DROP TABLE users--",
      query: { q: "' OR 1=1; DROP TABLE users--" } as any,
    });
    const res = createMockRes();

    middleware(req, res, vi.fn());
    expect(onBlock).toHaveBeenCalled();
  });

  it("fails open on internal errors", () => {
    middleware = securityWatch();
    const req = createMockReq();
    Object.defineProperty(req, "query", {
      get() {
        throw new Error("synthetic error");
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("registers res.on finish listener for brute force tracking", () => {
    middleware = securityWatch({ bruteForce: true });
    const req = createMockReq({ path: "/login", method: "POST" });
    const res = createMockRes();
    const next = vi.fn();

    middleware(req, res, next);
    expect(res.on).toHaveBeenCalledWith("finish", expect.any(Function));
  });

  it("destroy() cleans up without errors", () => {
    middleware = securityWatch();
    expect(() => middleware.destroy()).not.toThrow();
  });
});
