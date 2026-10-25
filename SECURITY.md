# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository
(Security tab → "Report a vulnerability"). Do not open a public issue.

We aim to acknowledge reports within 7 days.

## Scope

In scope: anything that lets this server change firewall state when it should
not, bypass the read allowlist or (once built) the write policy, leak API
credentials, or skip the audit log.

## Design notes

- Read path is GET-only with a path allowlist and verb denylist.
- No tool exists for reboot, firmware, service control, SSH or config XML.
- Secrets come only from environment variables and are never logged.
