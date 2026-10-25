"""The policy file: what this server may change.

Allowlist style. Anything not listed is refused. With no policy file the
server is read-only. The file is validated strictly (unknown keys are an
error, so a typo cannot silently widen or weaken a rule).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from opnsense_guard.config import ConfigError

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

RuleAction = Literal["pass", "block", "reject"]
RuleDirection = Literal["in", "out"]
AliasType = Literal["host", "network", "port"]

ALL_ACTIONS: tuple[RuleAction, ...] = ("pass", "block", "reject")
DEFAULT_DIRECTIONS: tuple[RuleDirection, ...] = ("in",)
ALL_ALIAS_TYPES: tuple[AliasType, ...] = ("host", "network", "port")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuleForbid(_Strict):
    any_to_any_pass: bool = True
    wan_inbound_pass: bool = True
    floating_rules: bool = True
    disable_logging: bool = True


class RulePolicy(_Strict):
    interfaces: list[str] = Field(default_factory=list)
    actions: list[RuleAction] = Field(default_factory=lambda: list(ALL_ACTIONS))
    directions: list[RuleDirection] = Field(default_factory=lambda: list(DEFAULT_DIRECTIONS))
    allow_networks: list[str] = Field(default_factory=list)
    forbid: RuleForbid = Field(default_factory=RuleForbid)
    protect_uuids: list[str] = Field(default_factory=list)

    @field_validator("allow_networks")
    @classmethod
    def _valid_networks(cls, value: list[str]) -> list[str]:
        for item in value:
            ipaddress.ip_network(item, strict=False)  # raises ValueError
        return value

    def networks(self) -> list[IPNetwork]:
        return [ipaddress.ip_network(n, strict=False) for n in self.allow_networks]


class AliasPolicy(_Strict):
    name_prefix: str = Field(default="mcp_", min_length=1)
    types: list[AliasType] = Field(default_factory=lambda: list(ALL_ALIAS_TYPES))
    max_entries: int = Field(default=64, ge=1, le=4096)


class WritePolicy(_Strict):
    confirm_timeout_s: int = Field(default=60, ge=10, le=600)
    max_objects_per_change: int = Field(default=5, ge=1, le=50)
    max_changes_per_hour: int = Field(default=10, ge=1, le=1000)
    require_human_confirm: bool = True
    tag: str = Field(default="[mcp]", min_length=1, max_length=32)
    only_modify_own: bool = True
    rules: RulePolicy = Field(default_factory=RulePolicy)
    aliases: AliasPolicy = Field(default_factory=AliasPolicy)


class AntiLockout(_Strict):
    enabled: bool = True
    # The MCP host's own addresses: no block/reject rule may match them as source.
    mcp_host_ips: list[str] = Field(default_factory=list)
    # Interfaces the MCP host reaches the API through: only new *pass* rules
    # may be added there (no block/reject, no edit/delete/disable).
    protected_interfaces: list[str] = Field(default_factory=list)
    # Turning anti-lockout off needs this second, explicit switch.
    i_understand_lockout_risk: bool = False

    @field_validator("mcp_host_ips")
    @classmethod
    def _valid_ips(cls, value: list[str]) -> list[str]:
        for item in value:
            ipaddress.ip_address(item)
        return value

    def host_ips(self) -> list[IPAddress]:
        return [ipaddress.ip_address(i) for i in self.mcp_host_ips]


class Policy(_Strict):
    mode: Literal["read_only", "write"] = "read_only"
    writes: WritePolicy = Field(default_factory=WritePolicy)
    anti_lockout: AntiLockout = Field(default_factory=AntiLockout)
    audit_reads: bool = False

    # Filled in by load_policy, not part of the file.
    source: str = Field(default="<built-in read-only default>", exclude=True)
    sha256: str = Field(default="", exclude=True)

    @property
    def writable(self) -> bool:
        return self.mode == "write"

    def summary(self) -> dict[str, Any]:
        """What the model should know about its limits."""
        data = self.model_dump(mode="json")
        data["policy_file"] = self.source
        data["policy_sha256"] = self.sha256
        return data


def _check_consistency(policy: Policy) -> None:
    lockout = policy.anti_lockout
    if not lockout.enabled and not lockout.i_understand_lockout_risk:
        raise ConfigError(
            "anti_lockout.enabled is false; also set anti_lockout.i_understand_lockout_risk: true "
            "to confirm you accept that a change may cut this server off from the firewall"
        )
    if policy.writable and lockout.enabled and not lockout.mcp_host_ips:
        raise ConfigError(
            "write mode needs anti_lockout.mcp_host_ips (this server's own IP addresses)"
        )


def load_policy(path: Path | None = None) -> Policy:
    """Load and validate the policy file. Missing file -> read-only default."""
    if path is None:
        path = Path(os.environ.get("OPNSENSE_GUARD_POLICY", "policy.yaml"))
    if not path.is_file():
        return Policy()

    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"policy file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"policy file {path} must be a mapping at the top level")
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"policy file {path} is invalid:\n{exc}") from exc

    policy = policy.model_copy(
        update={"source": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    )
    _check_consistency(policy)
    return policy
