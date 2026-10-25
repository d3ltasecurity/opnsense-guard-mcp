# opnsense-guard-mcp

A safety-first [MCP](https://modelcontextprotocol.io) server for **OPNsense 26.7+**.

> **Read-only by default. Every write is planned, policy-checked, logged, and
> auto-reverted unless you confirm it.**

**Status: pre-alpha (Phase 1).** Read tools over stdio or authenticated HTTP.
Writes, policy file and audit log are designed ([DESIGN.md](DESIGN.md)) but not built yet.

Not affiliated with Deciso B.V. "OPNsense" is a trademark of Deciso B.V.

## What makes it different

| | opnsense-guard-mcp |
|---|---|
| Default mode | read-only |
| Read path | GET only, path allowlist, verb denylist, traversal/encoding rejected, redirects not followed |
| Writes (planned) | separate API user, plan → policy check → apply → auto-revert unless confirmed |
| Rollback on 26.7+ (planned) | own object-level snapshot + revert (the savepoint API is gone in 26.7) |
| Guardrails (planned) | allowlist policy file: interfaces, networks, rule limits, anti-lockout |
| Audit (planned) | hash-chained JSONL + syslog |
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

## Tools (read-only)

`system_status`, `system_information`, `system_resources`, `service_list`,
`posture_check`, `suricata_status`, `suricata_settings`, `suricata_alert_status`,
`firewall_rules`, `firewall_rule_get`, `firewall_aliases`, `firewall_log`,
`firewall_states`, `system_log`, `interfaces`, `arp_table`, `routing_table`,
`dhcp_leases`, `raw_get`.

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
