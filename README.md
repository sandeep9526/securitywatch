# SecurityWatch

[![npm version](https://img.shields.io/npm/v/securitywatch.svg)](https://www.npmjs.com/package/securitywatch)
[![npm downloads](https://img.shields.io/npm/dm/securitywatch.svg)](https://www.npmjs.com/package/securitywatch)
[![license](https://img.shields.io/npm/l/securitywatch.svg)](https://github.com/sandeepsharmacode/securitywatch/blob/main/LICENSE)

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

### SQL injection (10 patterns)

| Pattern | Score | Example |
|---|---|---|
| Tautology | 5 | `' OR 1=1` |
| UNION SELECT | 5 | `1 UNION SELECT * FROM users` |
| Stacked queries | 6 | `1; DROP TABLE users` |
| Comment bypass + SQL keyword | 4 | `-- SELECT * FROM` |
| Encoded injection | 4 | `CHAR(0x75)` |
| Time-based blind | 5 | `SLEEP(5)` |
| NoSQL operators | 4 | `{"$gt": ""}` |
| Command execution | 6 | `xp_cmdshell`, `cmd.exe` |
| Schema manipulation | 6 | `DROP TABLE`, `ALTER TABLE` |
| Mass data export | 5 | `INTO OUTFILE`, `mysqldump` |

### XSS (7 patterns)

| Pattern | Score | Example |
|---|---|---|
| Script tag | 6 | `<script>alert(1)</script>` |
| javascript: protocol | 5 | `javascript:alert(1)` |
| Event handlers (20+ types) | 4 | `onerror=`, `onfocusin=` |
| Dangerous tags | 4 | `<iframe>`, `<svg>`, `<object>` |
| Data URI | 4 | `data:text/html,...` |
| eval/Function | 3 | `eval(...)` |
| Template injection | 3 | `${...}` |

### Suspicious behavior

| Pattern | Score |
|---|---|
| Sensitive path probing (/.env, /wp-admin, /.git, etc.) | 5 |
| Directory traversal (8 encoding variants) | 6 |
| Endpoint scanning (20+ unique routes/min) | 5 |
| Suspicious file extensions (.sql, .bak, .env) | 4 |
| Unusual HTTP methods on auth routes | 3 |

### Other

- **Rate limiting** — per-route limits with spike detection (3x threshold). Paths normalized to prevent key explosion.
- **Brute force** — progressive blocking via `res.on('finish')` status tracking. Counter resets on successful login.
- **Payload anomaly** — oversized payloads, null bytes, special char density, nesting depth.

## IP reputation

Scores accumulate per IP. Normal requests decrease score by 0.5. Decay of -1/min. Expires after 24h. Capped at 10K tracked IPs. IPs with score > 20 get +5 penalty on flagged requests.

## Using rules individually

```ts
import { detectSQLInjection, detectXSS } from "securitywatch";

detectSQLInjection("' OR 1=1--");
// { triggered: true, score: 5, rule: "sql-injection", reason: "SQL injection: tautology attack" }
```

## Accessing threat info

Warned requests have threat data on `req.securityWatch`:

```ts
app.get("/dashboard", (req, res) => {
  if (req.securityWatch) {
    console.log("Flagged:", req.securityWatch);
  }
  res.json({ ok: true });
});
```

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