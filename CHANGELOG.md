# Changelog

## 1.0.0 (2026-03-29)

Initial release.

- Added SQL injection detection (tautology, UNION, stacked queries, comment bypass, encoded, time-based blind, NoSQL, command exec, schema manipulation, data export)
- Added XSS detection (script tags, event handlers, javascript: protocol, dangerous tags, data URIs, eval, template injection)
- Added brute force protection with progressive blocking and counter reset on success
- Added per-route rate limiting with path normalization and spike detection
- Added suspicious behavior detection (path probing, directory traversal, endpoint scanning)
- Added payload anomaly detection (size, nesting depth, null bytes, special chars)
- Added IP reputation scoring with time decay
- Added route sensitivity multipliers
- Added Express middleware with configurable thresholds
- Added Slack webhook alerts
- Added IP whitelist and trustProxy config