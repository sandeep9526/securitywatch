import { describe, it, expect } from "vitest";
import { detectXSS } from "../src/core/rules/xss";

describe("XSS Detection", () => {
  it("detects script tags", () => {
    const result = detectXSS("<script>alert('xss')</script>");
    expect(result.triggered).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(6);
  });

  it("detects event handler injection", () => {
    const result = detectXSS('<img onerror="alert(1)">');
    expect(result.triggered).toBe(true);
    expect(result.reason).toContain("event handler");
  });

  it("detects javascript: protocol", () => {
    const result = detectXSS('javascript:alert(document.cookie)');
    expect(result.triggered).toBe(true);
  });

  it("detects iframe injection", () => {
    const result = detectXSS('<iframe src="http://evil.com">');
    expect(result.triggered).toBe(true);
  });

  it("detects svg injection", () => {
    const result = detectXSS('<svg onload="alert(1)">');
    expect(result.triggered).toBe(true);
  });

  it("detects data URI with HTML", () => {
    const result = detectXSS('data:text/html,<script>alert(1)</script>');
    expect(result.triggered).toBe(true);
  });

  it("allows normal HTML-like text", () => {
    const result = detectXSS("I love the <b>bold</b> approach");
    expect(result.triggered).toBe(false);
  });

  it("allows normal text", () => {
    const result = detectXSS("Just a regular comment about products");
    expect(result.triggered).toBe(false);
  });
});