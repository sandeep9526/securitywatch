import https from "https";
import http from "http";
import type { ThreatInfo, AlertConfig } from "../types";

export class AlertService {
  private config: AlertConfig;

  constructor(config: AlertConfig = { console: true }) {
    this.config = config;
  }

  send(info: ThreatInfo): void {
    if (this.config.slackWebhookUrl && (info.action === "block" || info.action === "throttle")) {
      this.sendSlack(info);
    }
  }

  private sendSlack(info: ThreatInfo): void {
    const reasons = info.results.map((r) => `• ${r.reason}`).join("\n");
    const emoji = info.action === "block" ? ":rotating_light:" : ":warning:";

    const payload = JSON.stringify({
      text: `${emoji} *SecurityWatch ${info.action.toUpperCase()}*\n` +
        `*IP:* ${info.ip}\n` +
        `*Request:* ${info.method} ${info.path}\n` +
        `*Score:* ${info.totalScore}\n` +
        `*Reasons:*\n${reasons}\n` +
        `*Time:* ${info.timestamp.toISOString()}`,
    });

    const url = new URL(this.config.slackWebhookUrl!);
    const transport = url.protocol === "https:" ? https : http;

    const req = transport.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        headers: { "Content-Type": "application/json" },
      },
      () => {} // fire-and-forget
    );

    req.on("error", () => {}); // silently ignore alert failures
    req.write(payload);
    req.end();
  }
}