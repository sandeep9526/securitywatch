import { describe, it, expect } from "vitest";
import { DetectionEngine } from "../src/core/engine";
import { MemoryStore } from "../src/store/memory";

describe("Detection Engine", () => {
  it("allows clean requests", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine({ sqlInjection: true, xss: true }, store);

    const result = engine.analyze({
      ip: "10.0.0.1",
      path: "/products",
      method: "GET",
      body: "",
      query: "page=1&limit=10",
    });

    expect(result.action).toBe("allow");
    expect(result.totalScore).toBe(0);
    engine.destroy();
    store.destroy();
  });

  it("blocks SQL injection attacks", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine(
      { sqlInjection: true, xss: true, thresholds: { warn: 3, throttle: 6, block: 10 } },
      store
    );

    const result = engine.analyze({
      ip: "10.0.0.2",
      path: "/search",
      method: "GET",
      query: "q=' OR 1=1; DROP TABLE users--",
    });

    expect(result.action).toBe("block");
    expect(result.results.length).toBeGreaterThan(0);
    engine.destroy();
    store.destroy();
  });

  it("applies route sensitivity multiplier", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine(
      {
        suspiciousBehavior: true,
        routeSensitivity: { "/admin": "critical" },
      },
      store
    );

    const result = engine.analyze({
      ip: "10.0.0.3",
      path: "/admin",
      method: "GET",
    });

    // Critical multiplier = 2x, so score should be doubled
    expect(result.totalScore).toBeGreaterThan(0);
    engine.destroy();
    store.destroy();
  });

  it("skips whitelisted IPs", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine({ whitelist: ["10.0.0.99"] }, store);

    expect(engine.isWhitelisted("10.0.0.99")).toBe(true);
    expect(engine.isWhitelisted("10.0.0.1")).toBe(false);
    engine.destroy();
    store.destroy();
  });

  it("combines multiple rule scores", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine(
      { sqlInjection: true, xss: true, thresholds: { warn: 3, throttle: 8, block: 12 } },
      store
    );

    // Input that triggers both SQL and XSS
    const result = engine.analyze({
      ip: "10.0.0.4",
      path: "/search",
      method: "GET",
      query: "q=<script>alert(1)</script>' OR 1=1--",
    });

    expect(result.results.length).toBeGreaterThanOrEqual(2);
    expect(result.totalScore).toBeGreaterThan(8);
    engine.destroy();
    store.destroy();
  });

  it("respects disabled rules", () => {
    const store = new MemoryStore();
    const engine = new DetectionEngine(
      {
        sqlInjection: false,
        xss: false,
        bruteForce: false,
        rateLimit: false,
        suspiciousBehavior: false,
        payloadAnomaly: false,
      },
      store
    );

    const result = engine.analyze({
      ip: "10.0.0.5",
      path: "/search",
      method: "GET",
      query: "q=' OR 1=1--",
    });

    expect(result.action).toBe("allow");
    expect(result.results.length).toBe(0);
    engine.destroy();
    store.destroy();
  });
});