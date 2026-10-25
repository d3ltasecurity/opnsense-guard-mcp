"""Entrypoint: build the MCP server and run it.

Phase 0 supports stdio only. HTTP arrives in Phase 1 together with token
auth, and the server refuses to start an unauthenticated HTTP listener.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from mcp.server import MCPServer

from opnsense_guard import __version__
from opnsense_guard.client import ReadClient
from opnsense_guard.config import ConfigError, load_dotenv, read_settings_from_env
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="opnsense-guard-mcp",
        description="Safety-first MCP server for OPNsense.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(os.environ.get("OPNSENSE_GUARD_ENV_FILE", ".env")),
        help="optional .env file to load (default: ./.env)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate configuration and exit (does not contact the firewall)",
    )
    args = parser.parse_args(argv)

    load_dotenv(args.env_file)

    if args.check:
        try:
            settings = read_settings_from_env()
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
        print(f"config ok: {settings.url} (verify={settings.verify})", file=sys.stderr)
        return

    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if transport != "stdio":
        print(
            f"MCP_TRANSPORT={transport!r} is not supported yet; HTTP with token "
            "auth arrives in a later release. Use stdio.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
