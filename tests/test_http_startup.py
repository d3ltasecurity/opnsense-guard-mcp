from pathlib import Path

import pytest

from opnsense_guard.auth import TokenStore
from opnsense_guard.config import ConfigError
from opnsense_guard.http import HttpSettings, http_settings_from_env, is_loopback, validate_startup
from opnsense_guard.server import main


@pytest.fixture
def store(tmp_path: Path) -> TokenStore:
    s = TokenStore(tmp_path / "tokens.json")
    s.create("laptop", "read")
    return s


def touch(path: Path) -> Path:
    path.write_text("x")
    return path


def test_loopback_with_token_ok(store: TokenStore) -> None:
    validate_startup(HttpSettings(tokens_file=store.path), store)


def test_no_tokens_refused(tmp_path: Path) -> None:
    empty = TokenStore(tmp_path / "none.json")
    with pytest.raises(ConfigError, match="no tokens"):
        validate_startup(HttpSettings(), empty)


def test_lan_bind_without_tls_refused(store: TokenStore) -> None:
    with pytest.raises(ConfigError, match="plain HTTP"):
        validate_startup(HttpSettings(host="0.0.0.0"), store)


def test_lan_bind_plaintext_opt_in(store: TokenStore) -> None:
    validate_startup(HttpSettings(host="0.0.0.0", allow_plaintext=True), store)


def test_lan_bind_with_tls_ok(store: TokenStore, tmp_path: Path) -> None:
    settings = HttpSettings(
        host="10.0.0.5",
        tls_cert=touch(tmp_path / "c.pem"),
        tls_key=touch(tmp_path / "k.pem"),
    )
    validate_startup(settings, store)


def test_tls_half_configured(store: TokenStore, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="both"):
        validate_startup(HttpSettings(tls_cert=touch(tmp_path / "c.pem")), store)


def test_mtls_needs_server_cert(store: TokenStore, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mTLS"):
        validate_startup(HttpSettings(tls_client_ca=touch(tmp_path / "ca.pem")), store)


def test_missing_tls_file(store: TokenStore, tmp_path: Path) -> None:
    settings = HttpSettings(tls_cert=tmp_path / "nope.pem", tls_key=touch(tmp_path / "k.pem"))
    with pytest.raises(ConfigError, match="not found"):
        validate_startup(settings, store)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


def test_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("MCP_HOST", "MCP_PORT", "MCP_ALLOWED_HOSTS", "MCP_ALLOWED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)
    settings = http_settings_from_env()
    assert settings.host == "127.0.0.1"
    assert settings.port == 8848
    assert "127.0.0.1:8848" in settings.allowed_hosts
    assert "localhost:8848" in settings.allowed_hosts
    assert settings.allowed_origins == []


def test_cli_refuses_http_without_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("OPNSENSE_GUARD_TOKENS_FILE", str(tmp_path / "none.json"))
    with pytest.raises(SystemExit) as exc:
        main(["--env-file", str(tmp_path / "none.env")])
    assert exc.value.code == 2


def test_cli_token_roundtrip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "t.json"
    env = ["--env-file", str(tmp_path / "none.env"), "--file", str(path)]
    main(["token", *env, "new", "--name", "hub", "--scope", "read"])
    token = capsys.readouterr().out.strip()
    assert token.startswith("ogm_")
    main(["token", *env, "list"])
    assert "hub\tread" in capsys.readouterr().out
    main(["token", *env, "revoke", "--name", "hub"])
    assert TokenStore(path).entries() == []
