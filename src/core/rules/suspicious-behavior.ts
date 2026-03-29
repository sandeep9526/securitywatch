import type { DetectionResult, Store } from "../../types";

const SENSITIVE_PATHS = [
  "/admin",
  "/.env",
  "/config",
  "/wp-admin",
  "/wp-login",
  "/phpmyadmin",
  "/.git",
  "/.htaccess",
  "/server-status",
  "/debug",
  "/actuator",
  "/graphql",
  "/api/v1/admin",
];

const SUSPICIOUS_EXTENSIONS = /\.(sql|bak|backup|old|orig|conf|log|ini|env)$/i;

export function createSuspiciousBehaviorDetector(store: Store) {
  return function detectSuspiciousBehavior(
    ip: string,
    path: string,
    method: string
  ): DetectionResult {
    let score = 0;
    const matched: string[] = [];

    // 1. Sensitive route probing
    const normalizedPath = path.toLowerCase();
    for (const sensitive of SENSITIVE_PATHS) {
      if (normalizedPath.startsWith(sensitive)) {
        score += 5;
        matched.push(`probing ${sensitive}`);
        break;
      }
    }

    // 2. Suspicious file extensions
    if (SUSPICIOUS_EXTENSIONS.test(path)) {
      score += 4;
      matched.push("suspicious file extension");
    }

    // 3. Directory traversal
    if (path.includes("..") || path.includes("%2e%2e")) {
      score += 6;
      matched.push("directory traversal attempt");
    }

    // 4. Endpoint scanning (many unique routes in short time)
    const routeSetKey = `sb:routes:${ip}`;
    const routes = store.get<string[]>(routeSetKey) ?? [];
    if (!routes.includes(path)) {
      routes.push(path);
      store.set(routeSetKey, routes, 60_000); // 1 minute window
    }
    if (routes.length > 20) {
      score += 5;
      matched.push(`endpoint scanning (${routes.length} unique routes in 1 min)`);
    }

    // 5. Invalid HTTP methods on common routes
    const unusualMethod =
      (method === "DELETE" || method === "PUT" || method === "PATCH") &&
      (normalizedPath === "/" || normalizedPath.startsWith("/login") || normalizedPath.startsWith("/signup"));
    if (unusualMethod) {
      score += 3;
      matched.push(`unusual ${method} on ${path}`);
    }

    return {
      triggered: score > 0,
      score,
      rule: "suspicious-behavior",
      reason: matched.length ? `Suspicious: ${matched.join(", ")}` : "",
    };
  };
}