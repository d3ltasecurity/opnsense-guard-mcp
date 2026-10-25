# opnsense-guard-mcp — design (draft v0.1, 2026-10-25)

A safety-first MCP server for OPNsense 26.7+. Python, MIT licence, published
under D3lta Security.

> **Status:** design only. No code yet.
>
> This file is meant to be public. Anything about a specific lab (IPs,
> interface names, rollout steps) lives in `local/`, which git ignores.

---

## 1. Why another OPNsense MCP

Existing servers (vespo92, Pixelworlds, lucamarien) each miss something:
no rollback on 26.7+ (the savepoint API is gone), blocklists instead of
allowlists, one identity for read and write, stdio only, or no guardrails at all.

opnsense-guard-mcp's promise, in one line:

> **Read-only by default. Every write is planned, policy-checked, logged, and
> auto-reverted unless you confirm it.**

## 2. Name

| Name | PyPI | GitHub | Verdict |
|---|---|---|---|
| `opnsense-mcp`, `opnsense-mcp-server`, `mcp-opnsense` | taken | taken | no |
| `opnguard` | free | `KipJM/OPNGuard` exists | no (clash) |
| **`opnsense-guard-mcp`** | **free** | **free** | **chosen** |
| `opnsense-warden`, `opnsense-sentry`, `opnsense-bastion`, `opnsense-steward` | free | free | considered |

- PyPI package: `opnsense-guard-mcp` · import: `opnsense_guard` · CLI: `opnsense-guard-mcp`
- GitHub: org `d3ltasecurity` (matches the d3ltasecurity.in domain).
  Repo: `d3ltasecurity/opnsense-guard-mcp`.
- "OPNsense" is a Deciso B.V. trademark. README says "for OPNsense", "not affiliated
  with Deciso". Other projects do the same.

Checked 2026-10-25 via the PyPI JSON API and GitHub search. Register both early.

## 3. Architecture

```
 MCP client (Claude Code, LangGraph…)
        │  stdio  ── or ──  Streamable HTTP + bearer token (+ optional mTLS)
        ▼
 ┌───────────────────────── opnsense-guard-mcp ─────────────────────────┐
 │ transport + auth  →  tool layer  →  policy engine  →  planner     │
 │                                         │                 │       │
 │                                    audit log (JSONL,   change     │
 │                                    hash-chained,       journal +  │
 │                                    optional syslog)    rollback   │
 │                                         │                 │       │
 │            ReadClient (GET only)   WriteClient (POST, allowlist)  │
 └──────────────┬───────────────────────────┬────────────────────────┘
                │ API user: mcp-readonly    │ API user: mcp-write
                ▼                           ▼
                     OPNsense REST API (26.7+)
```

Key rules:

1. **Two clients, two API users.** Reads use a user with `user-config-readonly`.
   Writes use a second user whose privileges cover only firewall rules + aliases.
   No write key configured → write tools are not even registered.
2. **Allowlist only.** Read client: GET + path-prefix allowlist + verb denylist
   (kept from the current server). Write client: POST to a fixed list of exact
   endpoints (`addRule`, `setRule`, `delRule`, `toggleRule`, `apply`, alias
   equivalents) — nothing else exists in code.
3. **No dangerous tools exist at all.** No reboot, halt, firmware, service
   restart, user/cert/VPN changes, no SSH, no XML config edits.
4. **Every write goes through the same pipeline:**
   `plan → policy check → (human confirm) → snapshot → apply → verify → confirm or auto-revert`.

Tech: Python 3.11+, official `mcp` SDK, `httpx` (async), `pydantic` for
models/config, `pyyaml` for the policy file. Tests with `pytest` + `respx`
(mocked OPNsense) and recorded fixtures from the lab.

### Code layout

```
src/opnsense_guard/
  config.py        env + policy loading/validation
  client/read.py   GET-only client (port of current opnsense_client.py)
  client/write.py  POST client, exact-endpoint allowlist
  policy.py        rule/alias guardrails
  planner.py       builds a plan + human-readable diff
  journal.py       change journal (SQLite) + snapshots
  rollback.py      revert timer, startup recovery
  audit.py         JSONL + syslog sink, hash chain, redaction
  auth.py          bearer tokens, scopes, Origin check
  tools/read.py    read tools
  tools/write.py   write tools
  server.py        entrypoint, transport selection
```

## 4. Tools

### Read (always on)

Ported from the current server: `system_status`, `system_information`,
`system_resources`, `service_list`, `posture_check`, `suricata_status`,
`suricata_settings`, `suricata_alert_status`, `firewall_rules`,
`firewall_aliases`, `firewall_log`, `firewall_states`, `system_log`,
`interfaces`, `arp_table`, `routing_table`, `dhcp_leases`, `raw_get`.

New:

| Tool | What it does |
|---|---|
| `firewall_rule_get` | one rule by UUID, full fields |
| `security_audit` | flags any→any pass rules, WAN inbound pass, rules without logging, disabled IDS, default creds hints, stale `[mcp]` rules |
| `policy_show` | what this server is allowed to change (so the model knows its limits) |
| `change_list` / `change_get` | the change journal: pending, confirmed, reverted |
| `audit_tail` | last N audit events (write scope only) |

### Write (only with write key + `mode: write` + a write-scoped token)

| Tool | What it does |
|---|---|
| `rule_plan` | add / update / delete / toggle one or more filter rules → returns `plan_id` + diff. **Changes nothing.** |
| `alias_plan` | create alias, add/remove entries, delete alias → `plan_id` + diff |
| `change_apply` | apply a plan; starts the revert timer; returns `change_id` |
| `change_confirm` | keep the change (stops the timer) |
| `change_rollback` | revert a change now (also works after confirm, within journal retention) |

Writes are always two calls (plan, then apply). The model cannot one-shot a
change. If the client supports MCP *elicitation*, `change_apply` also asks the
human "Apply plan X? (diff shown)" before doing anything.

## 5. Rollback on 26.7+ (the core feature)

The old savepoint API (`/api/firewall/filter/savepoint` + `cancelRollback`) is gone
in 26.7. We do it ourselves at object level.

**Apply:**

1. Re-read every object the plan touches (`getRule` / `getItem`). If it differs
   from what the plan was built on → abort ("changed since plan").
2. Store the **before** snapshot in the journal (SQLite on disk, fsync'd)
   *before* sending anything.
3. Send the writes, then `apply`. Record new UUIDs for added objects.
4. Re-read and store the **after** snapshot. Verify it matches the plan.
5. Health probe: a cheap GET (`/api/core/firmware/status`). If the API is no
   longer reachable → revert immediately (see lockout below).
6. Start the revert timer (default 60 s, policy-set, max 600 s).

**Revert** (timer expiry, `change_rollback`, or startup recovery):

| Original op | Revert |
|---|---|
| add | `delRule` the new UUID |
| update / toggle | `setRule` with the before snapshot |
| delete | `addRule` from the before snapshot (new UUID, noted in journal) |

Then `apply`. Before reverting, compare current state to the **after** snapshot.
If someone else edited the object meanwhile (e.g. another chat using the API
directly), **do not overwrite** — mark the change `conflict` and tell the user.

**Crash safety:** the journal is on disk. On startup the server finds any
change still `pending` past its deadline and reverts it. So a server crash or
restart does not leave an unconfirmed change in place.

**Lockout — honest limit.** The old savepoint ran *on the firewall*, so it
survived losing access. Ours runs on the MCP host. If a change cuts the MCP
host off from the API, the revert cannot reach the firewall. Mitigations:

- Policy refuses rules on the management interface (`lan`) and anything that
  matches the MCP host's own IP/path to the API (anti-lockout guard, on by default).
- The health probe after apply catches most self-lockouts within seconds.
- Optional later (Phase 5, needs thought): a firewall-side watchdog via
  OPNsense cron. Off by default because it widens the write user's privileges.

The README will state this limit plainly.

## 6. Policy file (`policy.yaml`)

Allowlist style: anything not listed is refused. Loaded at start, validated
with pydantic, hash written to the audit log.

```yaml
mode: read_only            # read_only | write   (default read_only)

writes:
  confirm_timeout_s: 60    # auto-revert after this unless change_confirm
  max_objects_per_change: 5
  max_changes_per_hour: 10
  require_human_confirm: true      # use MCP elicitation when available
  tag: "[mcp]"                     # prepended to every description we write
  only_modify_own: true            # update/delete only rules/aliases carrying the tag

  rules:
    interfaces: [opt1]             # your OPNsense interface tokens; never your mgmt iface or wan
    actions: [pass, block, reject]
    directions: [in]
    allow_networks:                # source/dest must sit inside these (or be an iface token)
      - 192.168.50.0/24            # example only
    forbid:
      any_to_any_pass: true
      wan_inbound_pass: true
      floating_rules: true
      disable_logging: true        # every rule we write has log=1
    protect_uuids: []              # rules that can never be touched

  aliases:
    name_prefix: "mcp_"            # can only create/edit aliases with this prefix
    types: [host, network, port]
    max_entries: 64

anti_lockout:
  enabled: true
  mcp_host_ips: [192.168.1.50]     # example: the MCP host; never block it → API
```

**Defaults vs. full control.** The defaults above are the safe starting point.
An operator who wants more can widen them: `only_modify_own: false` lets the
server edit any rule on the allowed interfaces, and more interfaces can be
listed. Some things stay fixed whatever the policy says: no reboot/firmware/
service tools exist, every write still goes plan → revert timer → audit log,
and turning off `anti_lockout` needs its own explicit setting.

The real `policy.yaml` is per install and is git-ignored; the repo ships
`policy.example.yaml` with placeholder addresses only.

Policy decisions (allow / deny + reason) go to the audit log, including refusals.

## 7. Audit log

- **Where:** `audit.jsonl` in the data dir (append-only, file mode 0600), plus
  optional syslog (RFC 5424, UDP/TCP/TLS) to Splunk / Elastic.
- **What:** every write-tool call and every policy refusal; reads optional
  (`audit_reads: false` by default to keep it small).
- **One line per event:**

```json
{"ts":"2026-10-25T12:00:00Z","event":"change_applied","change_id":"c_01H…",
 "plan_id":"p_01H…","actor":"token:laptop-claude","transport":"http",
 "client":"claude-code/2.x","tool":"change_apply","policy":"allow",
 "objects":[{"type":"rule","uuid":"…","op":"add"}],
 "before":null,"after":{…},"opnsense_status":"ok",
 "revert_deadline":"2026-10-25T12:01:00Z","policy_sha256":"…",
 "prev_hash":"…","hash":"…"}
```

- **Tamper-evident:** each line carries the SHA-256 of the previous line.
  `opnsense-guard-mcp audit verify` checks the chain.
- **Redaction:** API keys, tokens, `Authorization` headers never written.

## 8. Transports and auth

- **stdio** (default) — for a local Claude Code. No network exposure.
- **Streamable HTTP** — for a shared hub serving several clients.
  - Binds `127.0.0.1` by default.
  - **Bearer tokens required** for HTTP. Tokens stored as SHA-256 hashes in
    config; compared in constant time. Each token has a name + scope:
    `read` or `write`. A `read` token never sees write tools in `tools/list`.
  - **Refuses to start** if HTTP is on a non-loopback address without tokens,
    or if write mode is on and any token has no name.
  - `Origin` header check (MCP spec, stops DNS-rebinding).
  - TLS: built-in (cert + key paths) or behind a reverse proxy.
    Optional **mTLS** (client cert required).
  - Per-token rate limit.
  - CLI helper: `opnsense-guard-mcp token new --name laptop --scope read`
    prints the token once, stores the hash.

This closes a common gap: an HTTP MCP on `0.0.0.0` with no auth lets anyone
on the network call it.

## 9. Packaging and release

- `pyproject.toml` (hatchling), installable with `uv tool install opnsense-guard-mcp`
  or `pipx`.
- **PyPI** via GitHub Actions *Trusted Publishing* (no PyPI token stored),
  with build attestations.
- **Docker**: `python:3.12-slim`, non-root user, read-only root FS, one volume
  `/data` (journal + audit), healthcheck. Published to GHCR
  (`ghcr.io/d3ltasecurity/opnsense-guard-mcp`). Multi-arch amd64/arm64.
- Repo hygiene: `SECURITY.md` (how to report), `CHANGELOG.md`, Dependabot,
  CI (ruff, mypy, pytest), example `policy.yaml` + `.env.example`, no secrets.
- README: 2-minute quickstart, the comparison table, the threat model, the
  lockout limit, a demo GIF of plan → apply → auto-revert.

## 10. Phased build plan

Each phase ends with something working and tested against a mocked OPNsense.
Live-firewall testing happens in a lab, one change at a time.

| Phase | Deliverable | Writes to a firewall? |
|---|---|---|
| **0. Skeleton** | repo, pyproject, CI, read client + all read tools ported, unit tests with mocks, stdio works | no |
| **1. HTTP + auth** | Streamable HTTP, tokens, scopes, Origin check, TLS | no |
| **2. Policy + plans** | `policy.yaml`, `rule_plan`/`alias_plan` with diffs, `security_audit`, audit log | no |
| **3. Writes + rollback** | write client, journal, apply/confirm/rollback, startup recovery; tested with a harmless tagged block rule | **yes (lab)** |
| **4. Aliases + syslog** | alias writes, syslog sink, `audit verify`, elicitation confirm | yes (lab) |
| **5. Publish v0.1.0** | README, Docker, PyPI + GHCR, GitHub release. Later: firewall-side watchdog study | no |

## 11. Decisions (2026-10-25)

1. Name: `opnsense-guard-mcp`, GitHub org `d3ltasecurity`.
2. Default revert timer: **60 s** (configurable).
3. Write API user: **`mcp-write`** (pairs with `mcp-readonly`; tool-neutral).
4. `only_modify_own: true` by default; operators may opt into full control.
