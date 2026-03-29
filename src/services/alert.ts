import https from "https";
import type { ThreatInfo, AlertConfig } from "../types.js";

const ALLOWED_SLACK_HOSTS = ["hooks.slack.com", "hooks.slack-gov.com"];

function isAllowedWebhookUrl(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    if (url.protocol !== "https:") return false;
    return ALLOWED_SLACK_HOSTS.some(
      (host) => url.hostname === host || url.hostname.endsWith(`.${host}`)
    );
  } catch {
    return false;
  }
}

export class AlertService {
  private webhookUrl: string | undefined;

  constructor(config: AlertConfig = { console: true }) {
    if (config.slackWebhookUrl) {
      if (isAllowedWebhookUrl(config.slackWebhookUrl)) {
        this.webhookUrl = config.slackWebhookUrl;
      } else {
        console.warn(
          "[SecurityWatch] Invalid Slack webhook URL — must be HTTPS on hooks.slack.com. Slack alerts disabled."
        );
      }
    }
  }

  send(info: ThreatInfo): void {
    if (this.webhookUrl && (info.action === "block" || info.action === "throttle")) {
      this.sendSlack(info);
    }
  }

  private sendSlack(info: ThreatInfo): void {
    const reasons = info.results.map((r) => `• ${r.reason}`).join("\n");
    const emoji = info.action === "block" ? ":rotating_light:" : ":warning:";

    const payload = JSON.stringify({
      text:
        `${emoji} *SecurityWatch ${info.action.toUpperCase()}*\n` +
        `*IP:* ${info.ip}\n` +
        `*Request:* ${info.method} ${info.path}\n` +
        `*Score:* ${info.totalScore}\n` +
        `*Reasons:*\n${reasons}\n` +
        `*Time:* ${info.timestamp.toISOString()}`,
    });

    const url = new URL(this.webhookUrl!);

    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          console.warn(
            `[SecurityWatch] Slack alert failed with status ${res.statusCode}`
          );
        }
        // Drain the response
        res.resume();
      }
    );

    req.on("error", (err) => {
      console.warn(`[SecurityWatch] Slack alert failed: ${err.message}`);
    });

    req.write(payload);
    req.end();
  }
}