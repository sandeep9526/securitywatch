import { describe, it, expect, vi } from "vitest";
import { AlertService } from "../src/services/alert";
import type { ThreatInfo } from "../src/types";

function createThreatInfo(overrides: Partial<ThreatInfo> = {}): ThreatInfo {
  return {
    action: "block",
    totalScore: 20,
    ip: "10.0.0.1",
    path: "/search",
    method: "GET",
    results: [{ triggered: true, score: 20, rule: "sql-injection", reason: "tautology attack" }],
    timestamp: new Date("2026-01-01T00:00:00Z"),
    ...overrides,
  };
}

describe("AlertService", () => {
  it("creates without error when no config provided", () => {
    expect(() => new AlertService()).not.toThrow();
  });

  it("rejects non-Slack webhook URLs (SSRF protection)", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    new AlertService({
      slackWebhookUrl: "http://169.254.169.254/latest/meta-data/",
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Invalid Slack webhook URL")
    );
    warnSpy.mockRestore();
  });

  it("rejects non-HTTPS Slack URLs", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    new AlertService({
      slackWebhookUrl: "http://hooks.slack.com/services/xxx",
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Invalid Slack webhook URL")
    );
    warnSpy.mockRestore();
  });

  it("accepts valid Slack webhook URLs", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    new AlertService({
      slackWebhookUrl: "https://hooks.slack.com/services/T00/B00/xxx",
    });

    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it("does not send alerts for allowed requests", () => {
    const service = new AlertService({
      slackWebhookUrl: "https://hooks.slack.com/services/T00/B00/xxx",
    });

    // No error should be thrown even though we can't actually reach Slack
    expect(() =>
      service.send(createThreatInfo({ action: "allow" }))
    ).not.toThrow();
  });

  it("does not send alerts for warned requests", () => {
    const service = new AlertService({
      slackWebhookUrl: "https://hooks.slack.com/services/T00/B00/xxx",
    });

    expect(() =>
      service.send(createThreatInfo({ action: "warn" }))
    ).not.toThrow();
  });
});
