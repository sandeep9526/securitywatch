import type { DetectionResult, Store } from "../../types.js";

const SENSITIVE_PATHS = [
  "/admin", "/.env", "/config", "/wp-admin", "/wp-login",
  "/phpmyadmin", "/.git", "/.htaccess", "/server-status",
  "/debug", "/actuator", "/graphql", "/api/v1/admin",
];

const SUSPICIOUS_EXTENSIONS = /\.(sql|bak|backup|old|orig|conf|log|ini|env)$/i;

const MAX_TRACKED_ROUTES = 100;
const ENDPOINT_SCAN_THRESHOLD = 20;

export function createSuspiciousBehaviorDetector(store: Store) {
  return function detectSuspiciousBehavior(
    ip: string,
    path: string,
    method: string
  ): DetectionResult {
    let score = 0;
    const matched: string[] = [];
    const normalizedPath = path.toLowerCase();

    for (const sensitive of SENSITIVE_PATHS) {
      if (normalizedPath.startsWith(sensitive)) {
        score += 5;
        matched.push(`probing ${sensitive}`);
        break;
      }
    }

    if (SUSPICIOUS_EXTENSIONS.test(path)) {
      score += 4;
      matched.push("suspicious file extension");
    }

    if (
      path.includes("..") || path.includes("%2e%2e") ||
      path.includes("%2e.") || path.includes(".%2e") ||
      path.includes("%252e%252e") || path.includes("..%5c") ||
      path.includes("..%c0%af") || path.includes("..;/")
    ) {
      score += 6;
      matched.push("directory traversal attempt");
    }

    const routeSetKey = `sb:routes:${ip}`;
    const routes = store.get<string[]>(routeSetKey) ?? [];
    if (!routes.includes(path) && routes.length < MAX_TRACKED_ROUTES) {
      routes.push(path);
      store.set(routeSetKey, routes, 60_000);
    }
    if (routes.length > ENDPOINT_SCAN_THRESHOLD) {
      score += 5;
      matched.push(`endpoint scanning (${routes.length} unique routes in 1 min)`);
    }

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