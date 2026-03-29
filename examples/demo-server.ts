/**
 * SecurityWatch Demo Server
 *
 * Run: npx ts-node examples/demo-server.ts
 * Or:  npm run build && node examples/demo-server.js
 *
 * Then test with the curl commands printed on startup.
 */

import express from "express";
import { securityWatch } from "../src";

const app = express();
app.use(express.json());

// ── Attach SecurityWatch ──────────────────────────────────────────
app.use(
  securityWatch({
    sqlInjection: true,
    xss: true,
    bruteForce: {
      maxAttempts: 3,
      windowMs: 60_000,
      blockDurationMs: 5 * 60_000,
      authRoutes: ["/login"],
    },
    rateLimit: {
      windowMs: 60_000,
      maxRequests: 20,
      routes: { "/login": 5 },
    },
    suspiciousBehavior: true,
    payloadAnomaly: true,
    routeSensitivity: {
      "/admin": "critical",
      "/login": "high",
      "/search": "low",
    },
    whitelist: ["127.0.0.2"],
    alerts: { console: true },
    onBlock: (_req, info) => {
      console.log(`\n🚫 Blocked request from ${info.ip} — score ${info.totalScore}`);
    },
    onWarn: (_req, info) => {
      console.log(`\n⚠️  Warning for ${info.ip} — score ${info.totalScore}`);
    },
  })
);

// ── Demo routes ───────────────────────────────────────────────────

app.get("/", (_req, res) => {
  res.json({ status: "ok", message: "SecurityWatch is protecting this server" });
});

app.get("/search", (req, res) => {
  res.json({ query: req.query.q, results: [] });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  if (email === "admin@test.com" && password === "password123") {
    res.json({ token: "fake-jwt-token" });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

app.get("/admin", (_req, res) => {
  res.json({ admin: true, users: 42 });
});

app.get("/products", (_req, res) => {
  res.json([
    { id: 1, name: "Widget", price: 9.99 },
    { id: 2, name: "Gadget", price: 19.99 },
  ]);
});

// ── Start ─────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                  SecurityWatch Demo Server                   ║
║                  http://localhost:${PORT}                        ║
╠══════════════════════════════════════════════════════════════╣
║  Try these attacks:                                          ║
║                                                              ║
║  1. SQL Injection:                                           ║
║     curl "localhost:${PORT}/search?q=' OR 1=1--"                 ║
║                                                              ║
║  2. XSS:                                                     ║
║     curl "localhost:${PORT}/search?q=<script>alert(1)</script>"  ║
║                                                              ║
║  3. Brute Force (run 4+ times):                              ║
║     curl -X POST localhost:${PORT}/login \\                      ║
║       -H "Content-Type: application/json" \\                  ║
║       -d '{"email":"x","password":"y"}'                      ║
║                                                              ║
║  4. Admin Probing:                                           ║
║     curl localhost:${PORT}/.env                                  ║
║     curl localhost:${PORT}/wp-admin                              ║
║                                                              ║
║  5. Directory Traversal:                                     ║
║     curl "localhost:${PORT}/../../etc/passwd"                     ║
║                                                              ║
║  6. Normal request (should pass):                            ║
║     curl localhost:${PORT}/products                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
});