import { describe, it, expect } from "vitest";
import { detectSQLInjection } from "../src/core/rules/sql-injection";
import { detectXSS } from "../src/core/rules/xss";
import { detectPayloadAnomaly } from "../src/core/rules/payload-anomaly";
import { createSuspiciousBehaviorDetector } from "../src/core/rules/suspicious-behavior";
import { MemoryStore } from "../src/store/memory";

describe("Edge Cases", () => {
  describe("Empty and boundary inputs", () => {
    it("handles empty string for SQL injection", () => {
      const result = detectSQLInjection("");
      expect(result.triggered).toBe(false);
    });

    it("handles empty string for XSS", () => {
      const result = detectXSS("");
      expect(result.triggered).toBe(false);
    });

    it("handles empty string for payload anomaly", () => {
      const result = detectPayloadAnomaly("");
      expect(result.triggered).toBe(false);
    });
  });

  describe("Large inputs (ReDoS protection)", () => {
    it("handles very large input for SQL injection without hanging", () => {
      // This would cause ReDoS with unprotected regex
      const malicious = "--" + "A".repeat(50_000) + "SELECT";
      const start = Date.now();
      const result = detectSQLInjection(malicious);
      const elapsed = Date.now() - start;

      // Should complete in under 1 second (truncation protects us)
      expect(elapsed).toBeLessThan(1000);
      // The truncated input won't contain the SELECT at the end
      expect(result.triggered).toBe(false);
    });

    it("handles very large input for XSS without hanging", () => {
      const large = "x".repeat(50_000) + "<script>alert(1)</script>";
      const start = Date.now();
      detectXSS(large);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(1000);
    });
  });

  describe("Unicode and encoding", () => {
    it("handles Unicode in SQL injection", () => {
      const result = detectSQLInjection("名前は' OR 1=1--");
      expect(result.triggered).toBe(true);
    });

    it("handles Unicode in XSS", () => {
      const result = detectXSS("<script>alert('日本語')</script>");
      expect(result.triggered).toBe(true);
    });
  });

  describe("NoSQL injection", () => {
    it("detects MongoDB $gt operator", () => {
      const result = detectSQLInjection('{"password": {"$gt": ""}}');
      expect(result.triggered).toBe(true);
      expect(result.reason).toContain("NoSQL");
    });

    it("detects MongoDB $ne operator", () => {
      const result = detectSQLInjection('{"password": {"$ne": ""}}');
      expect(result.triggered).toBe(true);
    });

    it("detects MongoDB $where operator", () => {
      const result = detectSQLInjection('{"$where": "this.password == x"}');
      expect(result.triggered).toBe(true);
    });
  });

  describe("XSS extended vectors", () => {
    it("detects onmouseenter event handler", () => {
      const result = detectXSS('<div onmouseenter="alert(1)">');
      expect(result.triggered).toBe(true);
    });

    it("detects onfocusin event handler", () => {
      const result = detectXSS('<input onfocusin="alert(1)">');
      expect(result.triggered).toBe(true);
    });

    it("detects template literal injection", () => {
      const result = detectXSS("${alert(document.cookie)}");
      expect(result.triggered).toBe(true);
    });
  });

  describe("Payload anomaly nesting depth", () => {
    it("correctly measures actual nesting depth", () => {
      // Depth 3, not 3 brackets
      const input = '{a:{b:{c:1}}}';
      const result = detectPayloadAnomaly(input);
      // Depth 3 is not enough to trigger (threshold is 50)
      expect(result.triggered).toBe(false);
    });

    it("detects deeply nested structure", () => {
      const nested = "{".repeat(55) + "x" + "}".repeat(55);
      const result = detectPayloadAnomaly(nested);
      expect(result.triggered).toBe(true);
      expect(result.reason).toContain("deeply nested");
    });

    it("does NOT false-positive on flat arrays", () => {
      // Many elements but depth is only 1
      const flat = "[" + Array(100).fill("1").join(",") + "]";
      const result = detectPayloadAnomaly(flat);
      // Should NOT trigger nesting (depth is 1)
      // May trigger other rules like oversized if large enough
      expect(result.reason).not.toContain("nested");
    });
  });

  describe("Directory traversal variants", () => {
    it("detects %2e%2e encoding", () => {
      const store = new MemoryStore();
      const detect = createSuspiciousBehaviorDetector(store);

      const result = detect("10.0.0.1", "/files/%2e%2e/etc/passwd", "GET");
      expect(result.triggered).toBe(true);
      expect(result.reason).toContain("traversal");
      store.destroy();
    });

    it("detects double-encoded traversal", () => {
      const store = new MemoryStore();
      const detect = createSuspiciousBehaviorDetector(store);

      const result = detect("10.0.0.1", "/files/%252e%252e/etc/passwd", "GET");
      expect(result.triggered).toBe(true);
      store.destroy();
    });
  });
});
