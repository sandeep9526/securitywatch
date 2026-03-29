import type { Request, Response, NextFunction } from "express";
import type { SecurityConfig, SecurityWatchMiddleware } from "../types.js";
import { DetectionEngine } from "../core/engine.js";
import { MemoryStore } from "../store/memory.js";
import { AlertService } from "../services/alert.js";
import { logThreat } from "../services/logger.js";

function getClientIP(req: Request, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function extractInput(req: Request): string {
  const parts: string[] = [];

  if (req.query) {
    for (const value of Object.values(req.query)) {
      if (typeof value === "string") parts.push(value);
    }
  }

  if (req.body) {
    if (typeof req.body === "string") {
      parts.push(req.body);
    } else if (typeof req.body === "object") {
      try {
        parts.push(JSON.stringify(req.body));
      } catch {
        for (const val of Object.values(req.body as Record<string, unknown>)) {
          if (typeof val === "string") parts.push(val);
        }
      }
    }
  }

  if (req.params) {
    for (const value of Object.values(req.params)) {
      if (typeof value === "string") parts.push(value);
    }
  }

  return parts.join(" ");
}

function extractHeaders(req: Request): string {
  const scannable = ["referer", "user-agent", "cookie", "origin"];
  const parts: string[] = [];
  for (const header of scannable) {
    const val = req.headers[header];
    if (typeof val === "string") parts.push(val);
  }
  return parts.join(" ");
}

export function securityWatch(config: SecurityConfig = {}): SecurityWatchMiddleware {
  const store = new MemoryStore();
  const engine = new DetectionEngine(config, store);
  const alertConfig = config.alerts ?? { console: true };
  const alerts = new AlertService(alertConfig);
  const logEnabled = alertConfig.console !== false;
  const trustProxy = config.trustProxy ?? false;

  const middleware = (req: Request, res: Response, next: NextFunction): void => {
    try {
      const ip = getClientIP(req, trustProxy);

      if (engine.isWhitelisted(ip)) {
        next();
        return;
      }

      const input = extractInput(req);
      const headerInput = extractHeaders(req);

      const threat = engine.analyze({
        ip,
        path: req.path,
        method: req.method,
        body: input,
        query: req.url.includes("?") ? req.url.split("?")[1] : undefined,
        headers: headerInput,
      });

      res.on("finish", () => {
        try { engine.recordResponse(ip, req.path, res.statusCode); } catch {}
      });

      if (threat.action !== "allow") {
        if (logEnabled) logThreat(threat);
        alerts.send(threat);
      }

      switch (threat.action) {
        case "block":
          if (config.onBlock) config.onBlock(req, threat);
          res.status(403).json({ error: "Forbidden", message: "Request blocked by SecurityWatch" });
          return;

        case "throttle":
          if (config.onWarn) config.onWarn(req, threat);
          res.setHeader("Retry-After", "60");
          res.status(429).json({ error: "Too Many Requests", message: "You are being rate limited" });
          return;

        case "warn":
          if (config.onWarn) config.onWarn(req, threat);
          req.securityWatch = threat;
          next();
          return;

        default:
          next();
      }
    } catch (err) {
      if (logEnabled) console.error("[SecurityWatch] Internal error:", err);
      next();
    }
  };

  middleware.destroy = () => {
    engine.destroy();
    store.destroy();
  };

  return middleware;
}