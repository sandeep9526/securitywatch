import { describe, it, expect } from "vitest";
import { createBruteForceDetector } from "../src/core/rules/brute-force";
import { MemoryStore } from "../src/store/memory";

describe("Brute Force Detection", () => {
  it("allows initial login attempts", () => {
    const store = new MemoryStore();
    const detect = createBruteForceDetector(store, { maxAttempts: 5, windowMs: 60000, blockDurationMs: 300000 });

    const result = detect("192.168.1.1", "/login", 401);
    // First attempt — under threshold
    expect(result.score).toBeLessThan(7);
    store.destroy();
  });

  it("triggers after exceeding max attempts", () => {
    const store = new MemoryStore();
    const detect = createBruteForceDetector(store, { maxAttempts: 3, windowMs: 60000, blockDurationMs: 300000 });

    // Simulate 3 failed attempts
    detect("10.0.0.1", "/login", 401);
    detect("10.0.0.1", "/login", 401);
    const result = detect("10.0.0.1", "/login", 401);

    expect(result.triggered).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(7);
    store.destroy();
  });

  it("ignores non-auth routes", () => {
    const store = new MemoryStore();
    const detect = createBruteForceDetector(store);

    const result = detect("10.0.0.1", "/products", 404);
    expect(result.triggered).toBe(false);
    expect(result.score).toBe(0);
    store.destroy();
  });

  it("ignores successful logins", () => {
    const store = new MemoryStore();
    const detect = createBruteForceDetector(store, { maxAttempts: 3, windowMs: 60000, blockDurationMs: 300000 });

    // Successful attempts don't count
    detect("10.0.0.2", "/login", 200);
    detect("10.0.0.2", "/login", 200);
    detect("10.0.0.2", "/login", 200);
    const result = detect("10.0.0.2", "/login", 200);

    expect(result.triggered).toBe(false);
    store.destroy();
  });

  it("blocks IP after many failed attempts", () => {
    const store = new MemoryStore();
    const detect = createBruteForceDetector(store, { maxAttempts: 3, windowMs: 60000, blockDurationMs: 300000 });

    // 6+ attempts → block
    for (let i = 0; i < 6; i++) {
      detect("10.0.0.3", "/login", 401);
    }
    const result = detect("10.0.0.3", "/login", 401);
    expect(result.triggered).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(8);
    store.destroy();
  });
});