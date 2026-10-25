# opnsense-guard-mcp

A safety-first [MCP](https://modelcontextprotocol.io) server for **OPNsense 26.7+**.

> **Read-only by default. Every write is planned, policy-checked, logged, and
> auto-reverted unless you confirm it.**

**Status: pre-alpha (Phase 2).** Read tools, policy file, change *planning* with
diffs, and a hash-chained audit log, over stdio or authenticated HTTP. Applying
changes (with auto-revert) is designed ([DESIGN.md](DESIGN.md)) but not built yet.

Not affiliated with Deciso B.V. "OPNsense" is a trademark of Deciso B.V.

## What makes it different

| | opnsense-guard-mcp |
|---|---|
| Default mode | read-only |
| Read path | GET only, path allowlist, verb denylist, traversal/encoding rejected, redirects not followed |
| Writes (planned) | separate API user, plan → policy check → apply → auto-revert unless confirmed |
| Rollback on 26.7+ (planned) | own object-level snapshot + revert (the savepoint API is gone in 26.7) |
| Guardrails | allowlist policy file: interfaces, networks, rule limits, anti-lockout |
| Audit | hash-chained JSONL (`audit verify` detects edits); syslog planned |
| Transport | stdio, or Streamable HTTP that always needs a bearer token; optional TLS / mTLS |
| Dangerous tools | none exist: no reboot, firmware, service control, SSH or XML edits |

## Quick start (read-only)

1. In OPNsense, create an API user with **config read-only** set and
   privileges for the pages you want to expose. Create an API key for it.
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
