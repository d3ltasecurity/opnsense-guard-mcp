# Changelog

## Unreleased

- First real use: `firewall_rules` returned ~60 KB for 38 rules, too much for a
  chat. It now returns one line per rule (`total`, `shown`, `rows`), default
  limit 50, negation shown as `!`; `detail=true` gives the raw rows.
- `posture_check` reads `system_information` instead of `core/firmware/status`,
  so it works for the least-privilege read user.
- Change results always carry `change_id` (success used to say only `id`).
- HTTP shutdown gives open client streams 5 s. Before, an open Claude Code
  stream held shutdown until systemd killed the process (60 s), so the
  shutdown revert of unconfirmed changes never ran (startup recovery still
  caught them).

- Works with a least-privilege read user (tested on a real 26.7.4).
  OPNsense matches privileges against the literal snake_case URL, so the
  camelCase spellings (`getArp`) were refused for non-admin users even with
  the right privilege. ARP, routes, states and system info now use
  snake_case paths. The health probe moved from `core/firmware/status`
  (needs System: Firmware, which allows updates) to the dashboard's
  `system_information`. README lists the exact privileges for both users.
  The write user needs *Firewall: Alias: Edit*; *Firewall: Aliases* is view-only
  (found by the live alias test).
- Real 26.7.4 replies: a missing rule or alias name answers `[]`, and
  `getItem` for a missing alias uuid answers a blank template. The planner
  now treats a template whose name doesn't match as "absent"; the fake
  firewall in the tests matches these shapes.

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
