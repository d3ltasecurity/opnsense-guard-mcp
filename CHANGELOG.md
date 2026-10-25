# Changelog

## Unreleased

- Phase 3 (fake-firewall tested only): write client with an exact endpoint
  allowlist and a separate API user; SQLite change journal; `change_apply`
  with human approval (elicitation or explicit `user_confirmed`), drift check,
  verification read-back, health probe and full revert on any failure;
  automatic revert after `confirm_timeout_s`, on shutdown and on restart;
  `change_confirm`, `change_rollback` (conflict-safe), `change_list`,
  `change_get`; one open change at a time; hourly rate limit.
- Rule `sequence` is now part of plans, diffs and reverts, so an undone
  delete puts the rule back in the same place.

- Verified against a real OPNsense 26.7.4 `getRule` reply (fixture added).
  Plans now refuse rules using negation (`source_not`, `destination_not`,
  `interfacenot`) or non-quick matching; new rules always get quick=1 and no
  negation. `security_audit` skips OPNsense's automatic rules and treats
  empty nets as "any".

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
