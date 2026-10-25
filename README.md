# opnsense-guard-mcp

A safety-first [MCP](https://modelcontextprotocol.io) server for **OPNsense 26.7+**.

> **Read-only by default. Every write is planned, policy-checked, logged, and
> auto-reverted unless you confirm it.**

**Status: pre-alpha (Phase 0).** Read tools only. Writes, policy file, audit
log and authenticated HTTP are designed ([DESIGN.md](DESIGN.md)) but not built yet.

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
| Transport | stdio now; HTTP with bearer tokens / mTLS planned |
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
