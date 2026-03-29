import { describe, it, expect } from "vitest";
import { detectPayloadAnomaly } from "../src/core/rules/payload-anomaly";

describe("Payload Anomaly Detection", () => {
  it("detects oversized payloads", () => {
    const bigPayload = "A".repeat(15_000);
    const result = detectPayloadAnomaly(bigPayload);
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("oversized");
  });

  it("detects null byte injection", () => {
    const result = detectPayloadAnomaly("file.txt%00.jpg");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("null byte");
  });

  it("detects deeply nested structures", () => {
    const nested = "{".repeat(60) + "}".repeat(60);
    const result = detectPayloadAnomaly(nested);
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("nested");
  });

  it("allows normal payloads", () => {
    const result = detectPayloadAnomaly('{"name": "John", "email": "john@test.com"}');
    expect(result.triggered).toBe(false);
  });

  it("allows empty payloads", () => {
    const result = detectPayloadAnomaly("");
    expect(result.triggered).toBe(false);
  });
});