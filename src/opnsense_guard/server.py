"""Entrypoint: build the MCP server and run it, or manage HTTP tokens.

opnsense-guard-mcp                      serve (stdio, or HTTP if MCP_TRANSPORT=http)
opnsense-guard-mcp --check              validate config, do not contact the firewall
opnsense-guard-mcp token new|list|revoke
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from mcp.server import MCPServer

from opnsense_guard import __version__
from opnsense_guard.auth import SCOPES, TokenError, TokenStore
from opnsense_guard.client import ReadClient
from opnsense_guard.config import ConfigError, load_dotenv, read_settings_from_env
from opnsense_guard.http import http_settings_from_env, run_http
from opnsense_guard.tools.read import register_read_tools

INSTRUCTIONS = (
    "Read-only access to an OPNsense firewall. Tools return the firewall's "
    "JSON, or {'error': ...} if an endpoint is missing or not permitted. "
    "This server cannot change firewall state."
)


def build_server(get_client: Callable[[], ReadClient] | None = None) -> MCPServer:
    """Create the MCP server. ``get_client`` is injectable for tests."""
    mcp = MCPServer(
        "opnsense-guard-mcp",
        version=__version__,
        instructions=INSTRUCTIONS,
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
    return mcp


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

    parser = argparse.ArgumentParser(
        prog="opnsense-guard-mcp",
        description="Safety-first MCP server for OPNsense.",
        epilog="Token management: opnsense-guard-mcp token --help",
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

    if args.check:
        try:
            settings = read_settings_from_env()
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
        print(f"config ok: {settings.url} (verify={settings.verify})", file=sys.stderr)
        return

    if transport == "stdio":
        build_server().run(transport="stdio")
    elif transport in ("http", "streamable-http"):
        try:
            run_http(build_server(), http_settings_from_env())
        except (ConfigError, TokenError) as exc:
            print(f"refusing to start: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
    else:
        print(f"unknown MCP_TRANSPORT={transport!r}; use stdio or http", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
