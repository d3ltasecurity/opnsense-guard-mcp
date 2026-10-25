from pathlib import Path

import pytest

from opnsense_guard.config import ConfigError, load_dotenv, read_settings_from_env
from opnsense_guard.server import main

ENV_VARS = (
    "OPNSENSE_URL",
    "OPNSENSE_API_KEY",
    "OPNSENSE_API_SECRET",
    "OPNSENSE_VERIFY_SSL",
    "OPNSENSE_CA_BUNDLE",
    "OPNSENSE_TIMEOUT",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_missing_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPNSENSE_URL", "https://fw.test")
    with pytest.raises(ConfigError, match="OPNSENSE_API_KEY"):
        read_settings_from_env()


def test_url_needs_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPNSENSE_URL", "fw.test")
    monkeypatch.setenv("OPNSENSE_API_KEY", "k")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "s")
    with pytest.raises(ConfigError, match="scheme"):
        read_settings_from_env()


def test_verify_defaults_on_and_ca_bundle_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPNSENSE_URL", "https://fw.test/")
    monkeypatch.setenv("OPNSENSE_API_KEY", "k")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "s")
    settings = read_settings_from_env()
    assert settings.url == "https://fw.test"
    assert settings.verify is True
    monkeypatch.setenv("OPNSENSE_CA_BUNDLE", "/etc/fw-ca.pem")
    assert read_settings_from_env().verify == str(Path("/etc/fw-ca.pem"))


def test_secrets_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPNSENSE_URL", "https://fw.test")
    monkeypatch.setenv("OPNSENSE_API_KEY", "super-key")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "super-secret")
    text = repr(read_settings_from_env())
    assert "super-key" not in text
    assert "super-secret" not in text


def test_dotenv_does_not_override_real_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPNSENSE_URL=https://from-file\n# comment\nOPNSENSE_API_KEY='k'\n")
    monkeypatch.setenv("OPNSENSE_URL", "https://from-env")
    load_dotenv(env_file)
    import os

    assert os.environ["OPNSENSE_URL"] == "https://from-env"
    assert os.environ["OPNSENSE_API_KEY"] == "k"
    monkeypatch.delenv("OPNSENSE_API_KEY")


def test_check_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--check", "--env-file", str(tmp_path / "none.env")])
    assert exc.value.code == 2


def test_unknown_transport_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRANSPORT", "sse")
    with pytest.raises(SystemExit) as exc:
        main(["--env-file", str(tmp_path / "none.env")])
    assert exc.value.code == 2
