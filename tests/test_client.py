import json

import httpx
import pytest
import respx

from opnsense_guard.client import OPNsenseError, PathNotAllowed, ReadClient


async def test_get_returns_json(client: ReadClient, api: respx.MockRouter) -> None:
    route = api.get("/api/core/firmware/status").respond(json={"product_version": "26.7.4"})
    assert await client.get("/api/core/firmware/status") == {"product_version": "26.7.4"}
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.headers["authorization"].startswith("Basic ")


async def test_refused_path_never_hits_network(client: ReadClient, api: respx.MockRouter) -> None:
    with pytest.raises(PathNotAllowed):
        await client.get("/api/core/system/reboot")
    assert not api.calls


@pytest.mark.parametrize(
    ("status", "fragment"),
    [(401, "401"), (403, "403"), (404, "404"), (500, "HTTP 500"), (302, "redirect")],
)
async def test_http_errors(
    client: ReadClient, api: respx.MockRouter, status: int, fragment: str
) -> None:
    headers = {"location": "/"} if status == 302 else None
    api.get("/api/core/firmware/status").respond(status, headers=headers)
    with pytest.raises(OPNsenseError, match=fragment):
        await client.get("/api/core/firmware/status")


async def test_redirect_not_followed(client: ReadClient, api: respx.MockRouter) -> None:
    api.get("/api/core/firmware/status").respond(302, headers={"location": "/index.php"})
    login = api.get("/index.php").respond(200, text="<html>login</html>")
    with pytest.raises(OPNsenseError):
        await client.get("/api/core/firmware/status")
    assert not login.called


async def test_non_json_body(client: ReadClient, api: respx.MockRouter) -> None:
    api.get("/api/core/firmware/status").respond(200, text="<html>login</html>")
    with pytest.raises(OPNsenseError, match="expected JSON"):
        await client.get("/api/core/firmware/status")


async def test_connect_error(client: ReadClient, api: respx.MockRouter) -> None:
    api.get("/api/core/firmware/status").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(OPNsenseError, match="cannot reach"):
        await client.get("/api/core/firmware/status")


def test_client_has_no_write_methods() -> None:
    for name in ("post", "put", "patch", "delete", "request"):
        assert not hasattr(ReadClient, name)


async def test_search_posts_only_three_fields(client: ReadClient, api: respx.MockRouter) -> None:
    route = api.post("/api/diagnostics/firewall/query_states").respond(json={"rows": []})
    await client.search("/api/diagnostics/firewall/query_states", row_count=5, search_phrase="x")
    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {"current": 1, "rowCount": 5, "searchPhrase": "x"}


@pytest.mark.parametrize(
    "path",
    [
        "/api/firewall/filter/addRule",  # denied verb
        "/api/firewall/filter/apply",  # denied verb
        "/api/firewall/alias/searchItem",  # allowed for GET, not listed for POST
        "/api/diagnostics/firewall/query_states/extra",  # exact match only
        "/api/diagnostics/firewall/./query_states",  # traversal
    ],
)
async def test_search_refuses_unlisted_paths(
    client: ReadClient, api: respx.MockRouter, path: str
) -> None:
    with pytest.raises(PathNotAllowed):
        await client.search(path, row_count=5)
    assert not api.calls


async def test_search_refuses_long_phrase(client: ReadClient, api: respx.MockRouter) -> None:
    with pytest.raises(PathNotAllowed):
        await client.search("/api/firewall/filter/searchRule", row_count=5, search_phrase="a" * 201)
    assert not api.calls
