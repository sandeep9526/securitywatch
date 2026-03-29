import type { Request, Response, NextFunction } from "express";
import type { SecurityConfig } from "../types";
import { DetectionEngine } from "../core/engine";
import { MemoryStore } from "../store/memory";
import { AlertService } from "../services/alert";
import { logThreat } from "../services/logger";

function getClientIP(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}

function extractInput(req: Request): string {
  const parts: string[] = [];

  // Query string
  if (req.query) {
    parts.push(
      Object.values(req.query)
        .filter((v): v is string => typeof v === "string")
        .join(" ")
    );
  }

  // Body (string or object)
  if (req.body) {
    if (typeof req.body === "string") {
      parts.push(req.body);
    } else {
      try {
        parts.push(JSON.stringify(req.body));
      } catch {
        // ignore
      }
    }
  }

  // URL params
  if (req.params) {
    parts.push(Object.values(req.params).join(" "));
  }

  return parts.join(" ");
}

export function securityWatch(config: SecurityConfig = {}) {
  const store = new MemoryStore();
  const engine = new DetectionEngine(config, store);
  const alerts = new AlertService(config.alerts);

  const middleware = (req: Request, res: Response, next: NextFunction): void => {
    const ip = getClientIP(req);

    // Skip whitelisted IPs
    if (engine.isWhitelisted(ip)) {
      next();
      return;
    }

    const input = extractInput(req);

    const threat = engine.analyze({
      ip,
      path: req.path,
      method: req.method,
      body: typeof req.body === "string" ? req.body : input,
      query: req.url.includes("?") ? req.url.split("?")[1] : undefined,
    });

    // Log threats
    if (threat.action !== "allow") {
      logThreat(threat);
      alerts.send(threat);
    }

    // Handle actions
    switch (threat.action) {
      case "block":
        if (config.onBlock) config.onBlock(req, threat);
        res.status(403).json({
          error: "Forbidden",
          message: "Request blocked by SecurityWatch",
        });
        return;

      case "throttle":
        if (config.onWarn) config.onWarn(req, threat);
        res.setHeader("Retry-After", "60");
        res.status(429).json({
          error: "Too Many Requests",
          message: "You are being rate limited",
        });
        return;

      case "warn":
        if (config.onWarn) config.onWarn(req, threat);
        // Attach threat info to request for downstream use
        (req as any).securityWatch = threat;
        next();
        return;

      default:
        next();
    }
  };

  // Attach cleanup method
  (middleware as any).destroy = () => {
    engine.destroy();
    store.destroy();
  };

  return middleware;
}