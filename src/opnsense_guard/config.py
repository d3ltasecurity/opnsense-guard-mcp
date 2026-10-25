"""Settings, loaded from environment variables (and an optional .env file).

Secrets only ever come from the environment. Nothing here is logged.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr, field_validator

TRUTHY = ("1", "true", "yes", "on")


class ConfigError(RuntimeError):
    """Raised when required settings are missing or invalid."""


class ReadSettings(BaseModel):
    """Connection settings for the read-only API user."""

    url: str
    api_key: SecretStr
    api_secret: SecretStr
    verify_ssl: bool = True
    ca_bundle: Path | None = None
    timeout: float = Field(default=15.0, gt=0, le=120)

    @field_validator("url")
    @classmethod
    def _url_has_scheme(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("OPNSENSE_URL must include a scheme, e.g. https://10.0.0.1")
        return value.rstrip("/")

    @property
    def verify(self) -> bool | str:
        """Value for httpx's ``verify``: CA bundle path, True, or False."""
        if self.ca_bundle is not None:
            return str(self.ca_bundle)
        return self.verify_ssl


def load_dotenv(path: Path) -> None:
    """Minimal .env loader. Real environment variables always win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def read_settings_from_env() -> ReadSettings:
    """Build ReadSettings from OPNSENSE_* variables."""
    env = os.environ
    missing = [
        name
        for name in ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET")
        if not env.get(name)
    ]
    if missing:
        raise ConfigError(f"missing environment variables: {', '.join(missing)}")

    ca_bundle = env.get("OPNSENSE_CA_BUNDLE") or None
    try:
        return ReadSettings(
            url=env["OPNSENSE_URL"],
            api_key=SecretStr(env["OPNSENSE_API_KEY"]),
            api_secret=SecretStr(env["OPNSENSE_API_SECRET"]),
            verify_ssl=env.get("OPNSENSE_VERIFY_SSL", "true").lower() in TRUTHY,
            ca_bundle=Path(ca_bundle) if ca_bundle else None,
            timeout=float(env.get("OPNSENSE_TIMEOUT", "15")),
        )
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        raise ConfigError(str(exc)) from exc
