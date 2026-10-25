import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from opnsense_guard.auth import SlidingWindow, TokenError, TokenStore, hash_token
from opnsense_guard.http import HttpSettings, build_http_app
from opnsense_guard.server import build_server

HOST = "127.0.0.1:8848"
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}

# ------------------------------------------------------------- token store


def test_create_verify_revoke(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "tokens.json")
    token = store.create("laptop", "read")
    assert token.startswith("ogm_")
    entry = store.verify(token)
    assert entry is not None
    assert (entry.name, entry.scope) == ("laptop", "read")
    assert store.verify(token + "x") is None
    store.revoke("laptop")
    assert store.verify(token) is None


def test_plaintext_never_stored(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    token = TokenStore(path).create("laptop", "write")
    text = path.read_text()
    assert token not in text
    assert hash_token(token) in text


def test_duplicate_and_bad_names(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "tokens.json")
    store.create("laptop", "read")
    with pytest.raises(TokenError, match="already exists"):
        store.create("laptop", "read")
    for bad in ("", "has space", "../x", "a" * 65):
        with pytest.raises(TokenError):
            store.create(bad, "read")
    with pytest.raises(TokenError):
        store.create("ok", "admin")  # type: ignore[arg-type]
    with pytest.raises(TokenError, match="no token"):
        store.revoke("nobody")


def test_reload_on_change(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    serving = TokenStore(path)
    token = TokenStore(path).create("laptop", "read")
    assert serving.verify(token) is not None
    TokenStore(path).revoke("laptop")  # revoked by another process
    assert serving.verify(token) is None


def test_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    path.write_text("{not json")
    with pytest.raises(TokenError, match="malformed"):
        TokenStore(path).entries()
    path.write_text(json.dumps({"tokens": [{"name": "x", "scope": "root", "sha256": "0"}]}))
    with pytest.raises(TokenError, match="unknown scope"):
        TokenStore(path).entries()


def test_sliding_window() -> None:
    window = SlidingWindow(limit=2, window=60)
    assert window.allow("a", now=0)
    assert window.allow("a", now=1)
    assert not window.allow("a", now=2)
    assert window.allow("b", now=2)
    assert window.allow("a", now=61)


# ------------------------------------------------------------ middleware


@pytest.fixture
def token_store(tmp_path: Path) -> TokenStore:
    return TokenStore(tmp_path / "tokens.json")


@pytest.fixture
def token(token_store: TokenStore) -> str:
    return token_store.create("laptop", "read")


def make_client(store: TokenStore, **overrides: object) -> TestClient:
    settings = HttpSettings(tokens_file=store.path)
    settings.allowed_hosts = settings.default_hosts()
    for key, value in overrides.items():
        setattr(settings, key, value)
    app = build_http_app(build_server(), settings, store)
    return TestClient(app, base_url=f"http://{HOST}")


@pytest.fixture
def http(token_store: TokenStore, token: str) -> Iterator[TestClient]:
    with make_client(token_store) as client:
        yield client


def auth(token: str) -> dict[str, str]:
    return {**MCP_HEADERS, "authorization": f"Bearer {token}"}


def test_valid_token_reaches_mcp(http: TestClient, token: str) -> None:
    response = http.post("/mcp", json=INIT, headers=auth(token))
    assert response.status_code == 200
    assert "opnsense-guard-mcp" in response.text


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Bearer", "Bearer wrong", "Basic dXNlcjpwYXNz", "bearer  "],
)
def test_bad_or_missing_token(http: TestClient, authorization: str | None) -> None:
    headers = dict(MCP_HEADERS)
    if authorization is not None:
        headers["authorization"] = authorization
    response = http.post("/mcp", json=INIT, headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_every_path_needs_auth(http: TestClient) -> None:
    for path in ("/", "/mcp", "/health", "/docs"):
        assert http.get(path).status_code == 401


def test_bad_host_rejected(http: TestClient, token: str) -> None:
    response = http.post("/mcp", json=INIT, headers={**auth(token), "host": "evil.example:8848"})
    assert response.status_code == 421


def test_browser_origin_rejected_unless_allowed(token_store: TokenStore, token: str) -> None:
    with make_client(token_store) as client:
        headers = {**auth(token), "origin": "http://evil.example"}
        assert client.post("/mcp", json=INIT, headers=headers).status_code == 403
    with make_client(token_store, allowed_origins=["http://127.0.0.1:8848"]) as client:
        headers = {**auth(token), "origin": "http://127.0.0.1:8848"}
        assert client.post("/mcp", json=INIT, headers=headers).status_code == 200


def test_rate_limit_per_token(token_store: TokenStore, token: str) -> None:
    with make_client(token_store, rate_limit_per_min=2) as client:
        codes = [client.post("/mcp", json=INIT, headers=auth(token)).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_repeated_failures_get_throttled(http: TestClient, token: str) -> None:
    codes = [http.post("/mcp", json=INIT, headers=auth("ogm_wrong")).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429
    # even the right token is refused while throttled
    assert http.post("/mcp", json=INIT, headers=auth(token)).status_code == 429


def test_revoked_token_refused_without_restart(
    http: TestClient, token_store: TokenStore, token: str
) -> None:
    assert http.post("/mcp", json=INIT, headers=auth(token)).status_code == 200
    TokenStore(token_store.path).revoke("laptop")
    assert http.post("/mcp", json=INIT, headers=auth(token)).status_code == 401
