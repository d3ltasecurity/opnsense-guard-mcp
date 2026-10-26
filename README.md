# opnsense-guard-mcp

A safety-first [MCP](https://modelcontextprotocol.io) server for **OPNsense 26.7+**.

> **Read-only by default. Every write is planned, policy-checked, logged, and
> auto-reverted unless you confirm it.**

**Status: pre-alpha (Phase 3, not yet tested against a live firewall).** Read
tools, policy file, change planning with diffs, applying changes with verification
and automatic revert, and a hash-chained audit log, over stdio or authenticated
HTTP. See [DESIGN.md](DESIGN.md).

Not affiliated with Deciso B.V. "OPNsense" is a trademark of Deciso B.V.

## What makes it different

| | opnsense-guard-mcp |
|---|---|
| Default mode | read-only |
| Read path | GET only, path allowlist, verb denylist, traversal/encoding rejected, redirects not followed |
| Writes | separate API user, exact endpoint allowlist, plan → policy check → human approval → apply → verify → auto-revert unless confirmed |
| Rollback on 26.7+ | own object-level snapshots + revert (the savepoint API is gone in 26.7); survives restarts |
| Guardrails | allowlist policy file: interfaces, networks, rule limits, anti-lockout |
| Audit | hash-chained JSONL (`audit verify` detects edits); syslog planned |
| Transport | stdio, or Streamable HTTP that always needs a bearer token; optional TLS / mTLS |
| Dangerous tools | none exist: no reboot, firmware, service control, SSH or XML edits |

## Quick start (read-only)

1. In OPNsense (**System → Access → Users**), create a user with a scrambled
   password, **no group** (not `admins`) and these privileges, then create an
   API key for it. Skip any that aren't installed; the matching tool just
   reports "forbidden".

   | Privilege | Used by |
   |---|---|
   | Firewall: Rules [new] | `firewall_rules`, `firewall_rule_get`, planning |
   | Firewall: Aliases (view-only) | `firewall_aliases`, planning |
   | Status: Interfaces | `interfaces` |
   | Status: Services | `service_list` |
   | Diagnostics: ARP Table | `arp_table` |
   | Diagnostics: Routing tables | `routing_table` |
   | Diagnostics: Show States | `firewall_states` |
   | Diagnostics: Logs: Firewall: Live View | `firewall_log` |
   | Diagnostics: Logs: System | `system_log` |
   | Lobby: Dashboard | `system_information`, `system_resources`, health probe |
   | Services: Intrusion Detection | `suricata_*` |
   | Services: DHCP: Kea(v4) / Services: Dnsmasq DNS/DHCP: Settings | `dhcp_leases` |
   | System: Firmware *(optional)* | `system_status`. It also allows installing updates, so leave it out unless you need it. |

   Most OPNsense privileges are not view-only (*Firewall: Aliases* is an
   exception): several of these also allow edits through the API. The server itself only ever sends GET requests with
   this key, but keep the list short.
2. Install:

   ```bash
   pipx install opnsense-guard-mcp   # not on PyPI yet; for now: pip install -e .
   ```

3. Configure (copy `.env.example` to `.env`, or set env vars):

   ```bash
   OPNSENSE_URL=https://firewall.example.internal
   OPNSENSE_API_KEY=...
   OPNSENSE_API_SECRET=...
   OPNSENSE_CA_BUNDLE=/path/to/firewall-ca.pem   # or OPNSENSE_VERIFY_SSL=false
   ```

4. Check the config (does not contact the firewall):

   ```bash
   opnsense-guard-mcp --check
   ```

5. Add to your MCP client, e.g. Claude Code:

   ```bash
   claude mcp add opnsense -- opnsense-guard-mcp --env-file /path/to/.env
   ```

## HTTP mode (shared server)

HTTP never runs without authentication. The server refuses to start if:

- there are no tokens, or
- it binds to a non-loopback address without TLS
  (override with `MCP_ALLOW_PLAINTEXT=true` only behind a TLS proxy).

1. Create a token per client. It is printed once; only its SHA-256 is stored:

   ```bash
   opnsense-guard-mcp token new --name laptop --scope read
   ```

   `token list` shows names and scopes; `token revoke --name laptop` takes
   effect on the next request, no restart needed.

2. Start the server:

   ```bash
   MCP_TRANSPORT=http MCP_HOST=0.0.0.0 MCP_PORT=8848 \
   MCP_TLS_CERT=server.pem MCP_TLS_KEY=server.key \
   opnsense-guard-mcp
   ```

3. Point the client at `https://<host>:8848/mcp` with header
   `Authorization: Bearer <token>`.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `8848` | listen address |
| `OPNSENSE_GUARD_TOKENS_FILE` | `./tokens.json` | token hashes |
| `MCP_TLS_CERT` / `MCP_TLS_KEY` | – | serve HTTPS |
| `MCP_TLS_CLIENT_CA` | – | require client certificates (mTLS) |
| `MCP_ALLOWED_HOSTS` | `localhost`/`127.0.0.1`/`MCP_HOST` on the port | accepted `Host` headers (DNS-rebinding guard) |
| `MCP_ALLOWED_ORIGINS` | none | browser origins allowed; any other `Origin` is refused |
| `MCP_RATE_LIMIT_PER_MIN` | `120` | requests per token per minute |
| `MCP_ALLOW_PLAINTEXT` | `false` | allow plain HTTP on a non-loopback address |

Repeated failed logins from one IP (10 a minute) are throttled with HTTP 429.

**Claude Code and a private CA:** Claude Code (Node) ignores the Windows/macOS
certificate store for MCP servers. Point `NODE_EXTRA_CA_CERTS` at your CA file
in the `env` block of `~/.claude/settings.json`, then fully quit and reopen
Claude, or the connection fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.

## Running in Docker

The image runs as a non-root user and keeps its audit log, change journal and
tokens in `/data`.

```bash
docker build -t opnsense-guard-mcp .

# stdio, for a local MCP client
docker run -i --rm --env-file .env -v guard-data:/data opnsense-guard-mcp

# HTTP: create a token, then serve (put the TLS files in the volume or mount them)
docker run --rm -v guard-data:/data opnsense-guard-mcp token new --name laptop --scope read
docker run -d --name opnsense-guard --env-file .env -v guard-data:/data -p 8848:8848 \
  -e MCP_TRANSPORT=http -e MCP_HOST=0.0.0.0 -e MCP_ALLOWED_HOSTS=mcp.example.internal:8848 \
  -e MCP_TLS_CERT=/data/tls/server.pem -e MCP_TLS_KEY=/data/tls/server.key \
  opnsense-guard-mcp
```

Mount a policy file and set `OPNSENSE_GUARD_POLICY` to enable writes. Stop the
container with `docker stop` (not `kill`) so unconfirmed changes are reverted.

## Policy and planning

Without a `policy.yaml` the server is read-only. To enable planning, copy
[`policy.example.yaml`](policy.example.yaml) to `policy.yaml` (or point
`OPNSENSE_GUARD_POLICY` at it) and edit it. Unknown keys are an error.

Planning tools (`rule_plan`, `alias_plan`) read the current state, apply every
policy check, and return a diff plus the reasons for any refusal. **They never
change the firewall.** Example result for a refused rule:

```
+ [wan] pass in inet any from any to any '[mcp]'
  interface 'wan' is not in the allowed interfaces
  any -> any pass rules are forbidden
  inbound pass rules on WAN are forbidden
  every rule written by this server must have logging on
```

Built-in guardrails: only listed interfaces/actions/directions; every IP inside
`allow_networks`; no any→any pass, WAN inbound pass, floating rules or rules
without logging; edit only rules tagged `[mcp]` (unless `only_modify_own: false`);
anti-lockout (no block rule that matches this server's own IP, and only new
pass rules on the interface it reaches the API through).

## Applying changes

Change tools appear only when **both** the policy is in write mode **and** a
second, write-capable API user is configured:

```bash
OPNSENSE_WRITE_API_KEY=...      # a different OPNsense user than the read one
OPNSENSE_WRITE_API_SECRET=...
```

Give that user exactly two privileges: **Firewall: Rules [new]** and
**Firewall: Alias: Edit**, no group. (Plain *Firewall: Aliases* is view-only:
it allows search/get but not addItem/setItem/delItem/reconfigure.) Over HTTP, the
change tools need a token with `--scope write`.

The flow:

1. `rule_plan` / `alias_plan` → diff + `plan_id` (changes nothing).
2. `change_apply(plan_id)` → asks the human to approve the diff (MCP
   elicitation where the client supports it; otherwise the tool returns the
   diff and must be called again with `user_confirmed=true`). Then it
   re-reads the firewall (refuses if anything drifted since planning), stores
   the before-state, writes, applies, reads everything back to verify, and
   checks the API is still reachable. Any failure → everything is reverted.
3. The change is **pending**: it is reverted automatically after
   `confirm_timeout_s` (default 60 s) unless `change_confirm` is called.
4. `change_rollback` undoes a pending or confirmed change. A revert never
   overwrites an object someone else edited meanwhile (status `conflict`).

Unconfirmed changes are also reverted when the server stops and, after a
crash, when it starts again. Only one change can be open at a time, and
`max_changes_per_hour` is enforced.

**Limits, stated plainly**

- The revert timer runs on the MCP host. If a change cuts that host off from
  the firewall API, the revert cannot reach it. The anti-lockout policy and
  the health probe right after apply exist to prevent and catch this, but they
  are not the same as the firewall-side savepoint older OPNsense versions had.
- Without elicitation, `user_confirmed=true` is the model's word that the user
  agreed. The audit log records which method was used.

## Audit log

Every plan (allowed or refused) and server start is written to
`$OPNSENSE_GUARD_DATA_DIR/audit.jsonl` (default `./data`). Each line holds the
hash of the previous one, so edits, deletions and reordering are detectable:

```bash
opnsense-guard-mcp audit verify
opnsense-guard-mcp audit tail -n 20
```

Credentials are never written to it.

## Tools (read-only)

`system_status`, `system_information`, `system_resources`, `service_list`,
`posture_check`, `suricata_status`, `suricata_settings`, `suricata_alert_status`,
`firewall_rules`, `firewall_rule_get`, `firewall_aliases`, `firewall_log`,
`firewall_states`, `system_log`, `interfaces`, `arp_table`, `routing_table`,
`dhcp_leases`, `raw_get`, `policy_show`, `security_audit`.

In write mode also: `rule_plan`, `alias_plan`, `plan_get`, `audit_tail`.
With write credentials also: `change_apply`, `change_confirm`, `change_rollback`,
`change_list`, `change_get`.

`firewall_rules` returns one line per rule (50 by default) so a full ruleset
fits in a chat; pass `detail=true` for the raw OPNsense rows, or use
`firewall_rule_get` for one rule.

Over HTTP, a read token still sees the change tools in the tool list, but
calling one is refused (`needs a token with scope 'write'`).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && mypy && pytest
```

## Security

See [SECURITY.md](SECURITY.md). Please report vulnerabilities privately.

## Licence

MIT. See [LICENSE](LICENSE).
