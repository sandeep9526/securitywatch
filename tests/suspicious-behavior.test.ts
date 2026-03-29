import { describe, it, expect } from "vitest";
import { createSuspiciousBehaviorDetector } from "../src/core/rules/suspicious-behavior";
import { MemoryStore } from "../src/store/memory";

describe("Suspicious Behavior Detection", () => {
  it("detects admin route probing", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/admin", "GET");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("probing");
    store.destroy();
  });

  it("detects .env access", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/.env", "GET");
    expect(result.triggered).toBe(true);
    store.destroy();
  });

  it("detects wp-admin probing", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/wp-admin", "GET");
    expect(result.triggered).toBe(true);
    store.destroy();
  });

  it("detects directory traversal", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/../../etc/passwd", "GET");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("directory traversal");
    store.destroy();
  });

  it("detects suspicious file extensions", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/backup/db.sql", "GET");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("suspicious file extension");
    store.destroy();
  });

  it("detects endpoint scanning", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    // Hit 21+ unique routes from same IP
    for (let i = 0; i < 21; i++) {
      detect("10.0.0.2", `/route-${i}`, "GET");
    }
    const result = detect("10.0.0.2", "/route-final", "GET");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("endpoint scanning");
    store.destroy();
  });

  it("detects unusual HTTP methods on auth routes", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/login", "DELETE");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("unusual DELETE");
    store.destroy();
  });

  it("allows normal requests", () => {
    const store = new MemoryStore();
    const detect = createSuspiciousBehaviorDetector(store);

    const result = detect("10.0.0.1", "/products", "GET");
    expect(result.triggered).toBe(false);
    store.destroy();
  });
});