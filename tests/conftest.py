from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
import respx
from mcp.server import MCPServer
from pydantic import SecretStr

from opnsense_guard.client import ReadClient
from opnsense_guard.config import ReadSettings
from opnsense_guard.server import build_server

BASE_URL = "https://fw.test"


@pytest.fixture
def settings() -> ReadSettings:
    return ReadSettings(
        url=BASE_URL,
        api_key=SecretStr("test-key"),
        api_secret=SecretStr("test-secret"),
    )


@pytest.fixture
async def client(settings: ReadSettings) -> AsyncIterator[ReadClient]:
    async with ReadClient(settings) as c:
        yield c


@pytest.fixture
def server(client: ReadClient) -> MCPServer:
    return build_server(lambda: client)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    # assert_all_mocked: any request we did not mock fails the test, so a
    # tool can never silently hit a real network.
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        yield router


async def call(server: MCPServer, name: str, args: dict[str, Any] | None = None) -> Any:
    """Call a tool and decode its JSON text result."""
    result = await server.call_tool(name, args or {})
    return json.loads(result.content[0].text)
