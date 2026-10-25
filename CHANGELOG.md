# Changelog

## Unreleased

- Phase 2: `policy.yaml` (strict, allowlist, read-only when absent),
  `rule_plan` / `alias_plan` with diffs and policy checks (never write),
  anti-lockout guard, `policy_show`, `security_audit`, `plan_get`,
  hash-chained audit log with `audit verify|tail`.

- Phase 1: Streamable HTTP transport. Bearer tokens (SHA-256 stored, named,
  read/write scope, `token new|list|revoke`, revocation without restart),
  Host/Origin checks, per-token rate limit, failed-login throttling,
  optional TLS and mTLS. Refuses to start without tokens, or on a
  non-loopback address without TLS.

- Phase 0: project skeleton, GET-only read client (httpx, hardened path
  checks), 19 read-only tools, unit tests with a mocked OPNsense, CI.
