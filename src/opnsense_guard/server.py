"""Entrypoint: build the MCP server and run it, or manage HTTP tokens.

opnsense-guard-mcp                      serve (stdio, or HTTP if MCP_TRANSPORT=http)
opnsense-guard-mcp --check              validate config, do not contact the firewall
opnsense-guard-mcp token new|list|revoke
opnsense-guard-mcp audit verify|tail
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

from mcp.server import MCPServer

from opnsense_guard import __version__
from opnsense_guard.audit import AuditLog, verify
from opnsense_guard.auth import SCOPES, TokenError, TokenStore
from opnsense_guard.changes import ChangeManager
from opnsense_guard.client import ReadClient, WriteClient, write_settings_from_env
from opnsense_guard.config import ConfigError, load_dotenv, read_settings_from_env
from opnsense_guard.http import http_settings_from_env, run_http
from opnsense_guard.journal import Journal
from opnsense_guard.planner import Planner, PlanStore
from opnsense_guard.policy import Policy, load_policy
from opnsense_guard.tools.change import register_change_tools
from opnsense_guard.tools.plan import register_plan_tools
from opnsense_guard.tools.read import register_read_tools

READ_ONLY_INSTRUCTIONS = (
    "Read-only access to an OPNsense firewall. Tools return the firewall's "
    "JSON, or {'error': ...} if an endpoint is missing or not permitted. "
    "This server cannot change firewall state."
)
WRITE_INSTRUCTIONS = (
    "Access to an OPNsense firewall. Reads are free. Changes go through plans: "
    "call policy_show to learn the limits, then rule_plan / alias_plan, and show "
    "the returned diff to the user. Planning never changes the firewall. "
    "If change tools are available: change_apply only after the user approves the "
    "diff; every change auto-reverts unless change_confirm is called after testing."
)


def data_dir() -> Path:
    return Path(os.environ.get("OPNSENSE_GUARD_DATA_DIR", "data"))


def audit_path() -> Path:
    return data_dir() / "audit.jsonl"


def journal_path() -> Path:
    return data_dir() / "journal.sqlite"


def build_server(
    get_client: Callable[[], ReadClient] | None = None,
    policy: Policy | None = None,
    audit: AuditLog | None = None,
    get_write: Callable[[], WriteClient] | None = None,
    journal: Journal | None = None,
    timeout_s: float | None = None,
) -> MCPServer:
    """Create the MCP server. All arguments are injectable for tests.

    With no policy given the server is read-only (main() loads policy.yaml).
    Change tools appear only in write mode with write credentials configured.
    """
    policy = policy or Policy()
    audit = audit or AuditLog(audit_path())
    mcp = MCPServer(
        "opnsense-guard-mcp",
        version=__version__,
        instructions=WRITE_INSTRUCTIONS if policy.writable else READ_ONLY_INSTRUCTIONS,
    )

    if get_client is None:
        holder: dict[str, ReadClient] = {}

        def get_client() -> ReadClient:
            # Built lazily so the server still starts (and lists tools) when
            # env is incomplete; each tool call then reports the config error.
            if "client" not in holder:
                holder["client"] = ReadClient(read_settings_from_env())
            return holder["client"]

    register_read_tools(mcp, get_client)
    planner = register_plan_tools(
        mcp, policy, get_client, audit, Planner(policy, get_client, PlanStore())
    )

    if policy.writable and get_write is None and write_settings_from_env() is not None:
        write_holder: dict[str, WriteClient] = {}

        def get_write() -> WriteClient:
            if "client" not in write_holder:
                settings = write_settings_from_env()
                assert settings is not None
                write_holder["client"] = WriteClient(settings)
            return write_holder["client"]

    if policy.writable and get_write is not None:
        manager = ChangeManager(
            policy,
            planner,
            planner.store,
            journal or Journal(journal_path()),
            audit,
            get_client,
            get_write,
            timeout_s=timeout_s,
        )
        register_change_tools(mcp, manager, policy)
    return mcp


async def revert_unconfirmed(policy: Policy, audit: AuditLog, reason: str) -> int:
    """Revert every unconfirmed change in the journal (startup / shutdown).

    Uses its own short-lived clients so it can run outside the server's loop.
    """
    if not policy.writable or not journal_path().exists():
        return 0
    write_settings = write_settings_from_env()
    if write_settings is None:
        return 0
    journal = Journal(journal_path())
    if not journal.open_changes():
        journal.close()
        return 0
    read = ReadClient(read_settings_from_env())
    write = WriteClient(write_settings)
    try:
        manager = ChangeManager(
            policy,
            Planner(policy, lambda: read, PlanStore()),
            PlanStore(),
            journal,
            audit,
            lambda: read,
            lambda: write,
        )
        results = await manager.revert_all_open(reason)
        for r in results:
            print(f"{reason}: change {r['id']} -> {r['status']}", file=sys.stderr)
        return len(results)
    finally:
        await read.aclose()
        await write.aclose()
        journal.close()


def audit_main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="opnsense-guard-mcp audit", description="Inspect the audit log."
    )
    _env_file_arg(parser)
    parser.add_argument(
        "--file", type=Path, help="audit log (default: $OPNSENSE_GUARD_DATA_DIR/audit.jsonl)"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("verify", help="check the hash chain")
    tail = sub.add_parser("tail", help="print the last events")
    tail.add_argument("-n", type=int, default=20)
    args = parser.parse_args(argv)

    load_dotenv(args.env_file)
    path = args.file or audit_path()
    if args.action == "verify":
        ok, _, message = verify(path)
        print(f"{path}: {message}", file=sys.stderr if ok else sys.stdout)
        if not ok:
            raise SystemExit(1)
    else:
        for record in AuditLog(path).tail(args.n):
            print(json.dumps(record, ensure_ascii=False))


def _env_file_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(os.environ.get("OPNSENSE_GUARD_ENV_FILE", ".env")),
        help="optional .env file to load (default: ./.env)",
    )


def token_main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="opnsense-guard-mcp token", description="Manage HTTP bearer tokens."
    )
    _env_file_arg(parser)
    parser.add_argument(
        "--file",
        type=Path,
        help="token file (default: $OPNSENSE_GUARD_TOKENS_FILE or ./tokens.json)",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    new = sub.add_parser("new", help="create a token (printed once)")
    new.add_argument("--name", required=True)
    new.add_argument("--scope", choices=SCOPES, default="read")
    sub.add_parser("list", help="list token names and scopes")
    revoke = sub.add_parser("revoke", help="delete a token")
    revoke.add_argument("--name", required=True)
    args = parser.parse_args(argv)

    load_dotenv(args.env_file)
    path = args.file or Path(os.environ.get("OPNSENSE_GUARD_TOKENS_FILE", "tokens.json"))
    store = TokenStore(path)
    try:
        if args.action == "new":
            token = store.create(args.name, args.scope)
            print(f"Created token '{args.name}' (scope: {args.scope}) in {path}", file=sys.stderr)
            print("Copy it now. It will not be shown again:", file=sys.stderr)
            print(token)
        elif args.action == "list":
            entries = store.entries()
            if not entries:
                print(f"no tokens in {path}", file=sys.stderr)
            for e in entries:
                print(f"{e.name}\t{e.scope}\t{e.created}")
        elif args.action == "revoke":
            store.revoke(args.name)
            print(f"Revoked token '{args.name}'", file=sys.stderr)
    except TokenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["token"]:
        token_main(argv[1:])
        return
    if argv[:1] == ["audit"]:
        audit_main(argv[1:])
        return

    parser = argparse.ArgumentParser(
        prog="opnsense-guard-mcp",
        description="Safety-first MCP server for OPNsense.",
        epilog="Subcommands: token --help, audit --help",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _env_file_arg(parser)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate configuration and exit (does not contact the firewall)",
    )
    args = parser.parse_args(argv)

    load_dotenv(args.env_file)
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()

    try:
        policy = load_policy()
    except ConfigError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    if args.check:
        try:
            settings = read_settings_from_env()
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
        print(f"config ok: {settings.url} (verify={settings.verify})", file=sys.stderr)
        print(f"policy ok: {policy.source} mode={policy.mode}", file=sys.stderr)
        return

    if transport not in ("stdio", "http", "streamable-http"):
        print(f"unknown MCP_TRANSPORT={transport!r}; use stdio or http", file=sys.stderr)
        raise SystemExit(2)

    audit = AuditLog(audit_path())
    audit.append(
        "server_started",
        version=__version__,
        transport=transport,
        policy_file=policy.source,
        policy_sha256=policy.sha256,
        mode=policy.mode,
    )
    try:
        # A change still open from a previous run was never confirmed: undo it.
        asyncio.run(revert_unconfirmed(policy, audit, "startup recovery"))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    server = build_server(policy=policy, audit=audit)

    try:
        if transport == "stdio":
            server.run(transport="stdio")
        else:
            run_http(server, http_settings_from_env())
    except (ConfigError, TokenError) as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    finally:
        # Unconfirmed changes do not outlive the server.
        asyncio.run(revert_unconfirmed(policy, audit, "shutdown"))


if __name__ == "__main__":
    main()
