import express from "express";
import { securityWatch } from "../src/index.js";

const app = express();
app.use(express.json());

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
  })
);

app.get("/", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/search", (req, res) => {
  res.json({ query: req.query.q, results: [] });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  if (email === "admin@test.com" && password === "test") {
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

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`SecurityWatch demo running on http://localhost:${PORT}`);
  console.log(`Try: curl "localhost:${PORT}/search?q=' OR 1=1--"`);
});