# SecurityWatch

Runtime security engine for Node.js apps. Detect and block SQL injection, XSS, brute force, endpoint scanning, and more — in one middleware.

```bash
npm install securitywatch
```

```ts
import express from "express";
import { securityWatch } from "securitywatch";

const app = express();

app.use(securityWatch());

app.listen(3000);
// That's it. Your app is now protected.
```

## Why SecurityWatch?

Most security tools today are either too basic (Helmet = headers only) or too heavy (WAFs, SIEMs). SecurityWatch fills the gap:

| Tool | What it does | Limitation |
|---|---|---|
| Helmet | HTTP security headers | No attack detection |
| express-rate-limit | Basic rate limiting | Not intelligent |
| Snyk / Semgrep | Static code scanning | Not runtime |
| WAFs (Cloudflare) | External traffic filter | Expensive, not customizable |
| **SecurityWatch** | **Runtime detection + scoring** | **This is the missing layer** |

## Features

- **SQL Injection Detection** — tautology, UNION, stacked queries, blind injection, encoding bypass
- **XSS Detection** — script tags, event handlers, javascript: protocol, dangerous HTML tags
- **Brute Force Protection** — progressive blocking (warn → block 15min → block 24hr)
- **Smart Rate Limiting** — per-route limits + traffic spike detection
- **Suspicious Behavior Detection** — endpoint scanning, admin probing, directory traversal
- **Payload Anomaly Detection** — oversized payloads, null bytes, deep nesting
- **IP Reputation Scoring** — score-based system with automatic time decay
- **Route Sensitivity** — critical routes get stricter scoring
- **Slack Alerts** — real-time notifications for blocks and throttles
- **Zero runtime dependencies** — only Express as a peer dependency

## How It Works

```
Request → Middleware → Run Detection Rules → Calculate Score → Decision
                                                                  │
                                              ┌───────────────────┤
                                              │                   │
                                         Score 0-4           Score 5-9
                                           ALLOW               WARN
                                              │                   │
                                         Score 10-14         Score 15+
                                          THROTTLE             BLOCK
```

Every rule returns a **score**, not a binary yes/no. Scores are combined, multiplied by route sensitivity, and checked against thresholds. This dramatically reduces false positives.

## Configuration

```ts
app.use(securityWatch({
  // Toggle rules (all enabled by default)
  sqlInjection: true,
  xss: true,
  bruteForce: true,
  rateLimit: true,
  suspiciousBehavior: true,
  payloadAnomaly: true,

  // Brute force config
  bruteForce: {
    maxAttempts: 5,          // attempts before warning
    windowMs: 5 * 60_000,   // 5 minute window
    blockDurationMs: 15 * 60_000,  // block for 15 minutes
    authRoutes: ["/login", "/auth"],
  },

  // Rate limiting config
  rateLimit: {
    windowMs: 60_000,       // 1 minute window
    maxRequests: 100,        // global limit
    routes: {                // per-route overrides
      "/login": 5,
      "/api": 60,
    },
  },

  // Route sensitivity (multiplies scores)
  // low=0.5x, medium=1x, high=1.5x, critical=2x
  routeSensitivity: {
    "/admin": "critical",
    "/login": "high",
    "/search": "low",
  },

  // Score thresholds
  thresholds: {
    warn: 5,
    throttle: 10,
    block: 15,
  },

  // Skip trusted IPs
  whitelist: ["127.0.0.1"],

  // Slack alerts for blocks/throttles
  alerts: {
    slackWebhookUrl: "https://hooks.slack.com/services/...",
  },

  // Custom callbacks
  onBlock: (req, threatInfo) => {
    console.log(`Blocked: ${threatInfo.ip}`);
  },
  onWarn: (req, threatInfo) => {
    console.log(`Warning: ${threatInfo.ip}`);
  },
}));
```

## Accessing Threat Info

When a request is warned (not blocked), threat info is attached to the request:

```ts
app.get("/dashboard", (req, res) => {
  if (req.securityWatch) {
    console.log("This request was flagged:", req.securityWatch);
  }
  res.json({ ok: true });
});
```

## Using Individual Rules

You can use detection rules independently:

```ts
import { detectSQLInjection, detectXSS, detectPayloadAnomaly } from "securitywatch";

const result = detectSQLInjection("' OR 1=1--");
// { triggered: true, score: 5, rule: "sql-injection", reason: "SQL injection: tautology attack" }

const xssResult = detectXSS("<script>alert(1)</script>");
// { triggered: true, score: 6, rule: "xss", reason: "XSS: script tag" }
```

## Demo Server

Run the included demo to test attacks interactively:

```bash
git clone https://github.com/YOUR_USERNAME/securitywatch
cd securitywatch
npm install
npx ts-node examples/demo-server.ts
```

Then try:

```bash
# SQL Injection (blocked)
curl "localhost:3000/search?q=' OR 1=1--"

# XSS (blocked)
curl "localhost:3000/search?q=<script>alert(1)</script>"

# Normal request (allowed)
curl localhost:3000/products
```

## Detection Rules

### SQL Injection
| Pattern | Score | Example |
|---|---|---|
| Tautology | 5 | `' OR 1=1` |
| UNION SELECT | 5 | `1 UNION SELECT * FROM users` |
| Stacked queries | 6 | `1; DROP TABLE users` |
| Comment bypass + SQL | 4 | `-- SELECT * FROM` |
| Encoded injection | 4 | `CHAR(0x75)` |
| Time-based blind | 5 | `SLEEP(5)` |

### XSS
| Pattern | Score | Example |
|---|---|---|
| Script tag | 6 | `<script>alert(1)</script>` |
| javascript: protocol | 5 | `javascript:alert(1)` |
| Event handlers | 4 | `onerror=alert(1)` |
| Dangerous tags | 4 | `<iframe>`, `<svg>`, `<object>` |
| Data URI | 4 | `data:text/html,...` |
| eval/Function | 3 | `eval(...)` |

### Suspicious Behavior
| Pattern | Score |
|---|---|
| Sensitive route probing (/.env, /wp-admin) | 5 |
| Directory traversal (../) | 6 |
| Endpoint scanning (20+ routes/min) | 5 |
| Suspicious file extensions (.sql, .bak) | 4 |
| Unusual HTTP methods on auth routes | 3 |

## IP Reputation

Every IP gets a reputation score that accumulates across requests:
- Malicious request → score **increases** by rule score
- Normal request → score **decreases** by 0.5
- Automatic decay: **-1 point per minute**
- Score expires after 24 hours

High-reputation IPs (score > 20) get an automatic +5 penalty on flagged requests.

## License

MIT