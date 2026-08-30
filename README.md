# SecurityWatch

[![npm version](https://img.shields.io/npm/v/securitywatch.svg)](https://www.npmjs.com/package/securitywatch)
[![npm downloads](https://img.shields.io/npm/dm/securitywatch.svg)](https://www.npmjs.com/package/securitywatch)
[![license](https://img.shields.io/npm/l/securitywatch.svg)](https://github.com/sandeepsharmacode/securitywatch/blob/main/LICENSE)
[![NPM Version](https://img.shields.io/npm/v/securitywatch.svg)](https://www.npmjs.com/package/securitywatch)

**Website**: [https://securitywatch.sandeepsharmadev.in/](https://securitywatch.sandeepsharmadev.in/)

Score-based runtime security middleware for Express. Detects SQL injection, XSS, brute force, rate limit abuse, and suspicious request patterns.

## Install

```bash
npm install securitywatch
```

```ts
import express from "express";
import { securityWatch } from "securitywatch";

const app = express();
app.use(securityWatch());
app.listen(3000);
```

## How it works

Each incoming request is scanned by multiple detection rules. Every rule returns a numeric score (not a binary yes/no). Scores are summed, multiplied by route sensitivity, and compared against thresholds:

- **0-4** — allow
- **5-9** — warn (request passes, threat info attached to `req.securityWatch`)
- **10-14** — throttle (429 response)
- **15+** — block (403 response)

This reduces false positives compared to binary blocking.

## Configuration

```ts
app.use(securityWatch({
  sqlInjection: true,
  xss: true,
  bruteForce: {
    maxAttempts: 5,
    windowMs: 5 * 60_000,
    blockDurationMs: 15 * 60_000,
    authRoutes: ["/login", "/auth"],
  },
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    routes: { "/login": 5, "/api": 60 },
  },
  suspiciousBehavior: true,
  payloadAnomaly: true,
  ipReputation: true,

  // low=0.5x, medium=1x (default), high=1.5x, critical=2x
  routeSensitivity: {
    "/admin": "critical",
    "/login": "high",
    "/search": "low",
  },

  thresholds: { warn: 5, throttle: 10, block: 15 },
  whitelist: ["127.0.0.1"],
  trustProxy: false, // set true only behind a trusted reverse proxy

  alerts: {
    console: true,
    slackWebhookUrl: "https://hooks.slack.com/services/...",
  },

  onBlock: (req, info) => console.log(`Blocked: ${info.ip}`),
  onWarn: (req, info) => console.log(`Warning: ${info.ip}`),
}));
```

## Detection rules

## Security notes

- All regex uses bounded quantifiers. Input truncated to 20K chars before scanning.
- `X-Forwarded-For` ignored by default. Set `trustProxy: true` only behind a trusted proxy.
- Slack webhook URLs validated against `hooks.slack.com` (HTTPS only).
- Internal errors are caught and logged. Requests proceed normally (fail-open).
- Headers scanned: Referer, User-Agent, Cookie, Origin.
- Memory bounded: IP tracking capped at 10K, route tracking at 100/IP, rate-limit keys normalized.

## Requirements

- Node.js >= 18
- Express >= 5

## License

MIT