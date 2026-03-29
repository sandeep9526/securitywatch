import { describe, it, expect } from "vitest";
import { createRateLimiter } from "../src/core/rules/rate-limit";
import { MemoryStore } from "../src/store/memory";

describe("Rate Limiting", () => {
  it("allows requests under the limit", () => {
    const store = new MemoryStore();
    const detect = createRateLimiter(store, { windowMs: 60000, maxRequests: 10 });

    const result = detect("10.0.0.1", "/api/data");
    expect(result.triggered).toBe(false);
    store.destroy();
  });

  it("triggers when exceeding limit", () => {
    const store = new MemoryStore();
    const detect = createRateLimiter(store, { windowMs: 60000, maxRequests: 5 });

    for (let i = 0; i < 5; i++) {
      detect("10.0.0.2", "/api/data");
    }
    const result = detect("10.0.0.2", "/api/data");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("Rate limit exceeded");
    store.destroy();
  });

  it("uses route-specific limits", () => {
    const store = new MemoryStore();
    const detect = createRateLimiter(store, {
      windowMs: 60000,
      maxRequests: 100,
      routes: { "/login": 3 },
    });

    detect("10.0.0.3", "/login");
    detect("10.0.0.3", "/login");
    detect("10.0.0.3", "/login");
    const result = detect("10.0.0.3", "/login");
    expect(result.triggered).toBe(true);
    store.destroy();
  });

  it("detects traffic spikes", () => {
    const store = new MemoryStore();
    const detect = createRateLimiter(store, { windowMs: 60000, maxRequests: 10 });

    // Exceed 3x the global limit (30+)
    for (let i = 0; i < 31; i++) {
      detect("10.0.0.4", `/path-${i}`);
    }
    const result = detect("10.0.0.4", "/final");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("spike");
    store.destroy();
  });

  it("tracks IPs independently", () => {
    const store = new MemoryStore();
    const detect = createRateLimiter(store, { windowMs: 60000, maxRequests: 3 });

    detect("10.0.0.5", "/api");
    detect("10.0.0.5", "/api");
    detect("10.0.0.5", "/api");

    // Different IP should still be allowed
    const result = detect("10.0.0.6", "/api");
    expect(result.triggered).toBe(false);
    store.destroy();
  });
});