import { describe, it, expect } from "vitest";
import { detectSQLInjection } from "../src/core/rules/sql-injection";

describe("SQL Injection Detection", () => {
  it("detects tautology attacks", () => {
    const result = detectSQLInjection("' OR 1=1");
    expect(result.triggered).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(5);
  });

  it("detects UNION SELECT", () => {
    const result = detectSQLInjection("1 UNION SELECT * FROM users");
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("UNION SELECT");
  });

  it("detects UNION ALL SELECT", () => {
    const result = detectSQLInjection("1 UNION ALL SELECT password FROM users");
    expect(result.triggered).toBe(true);
  });

  it("detects stacked queries", () => {
    const result = detectSQLInjection("1; DROP TABLE users");
    expect(result.triggered).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(6);
  });

  it("detects time-based blind injection", () => {
    const result = detectSQLInjection("1 AND SLEEP(5)");
    expect(result.triggered).toBe(true);
  });

  it("detects encoded injection", () => {
    const result = detectSQLInjection("CHAR(0x75,0x73,0x65,0x72)");
    expect(result.triggered).toBe(true);
  });

  it("allows normal text", () => {
    const result = detectSQLInjection("Hello, how are you?");
    expect(result.triggered).toBe(false);
    expect(result.score).toBe(0);
  });

  it("allows normal search queries", () => {
    const result = detectSQLInjection("blue widget size medium");
    expect(result.triggered).toBe(false);
  });

  it("allows email addresses", () => {
    const result = detectSQLInjection("user@example.com");
    expect(result.triggered).toBe(false);
  });
});