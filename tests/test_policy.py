from pathlib import Path

import pytest

from opnsense_guard.config import ConfigError
from opnsense_guard.policy import Policy, load_policy

ROOT = Path(__file__).resolve().parent.parent


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return path


def test_missing_file_is_read_only(tmp_path: Path) -> None:
    policy = load_policy(tmp_path / "nope.yaml")
    assert policy.mode == "read_only"
    assert not policy.writable


def test_example_policy_loads() -> None:
    policy = load_policy(ROOT / "policy.example.yaml")
    assert policy.writable
    assert policy.sha256
    assert policy.writes.rules.interfaces


def test_unknown_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid"):
        load_policy(write(tmp_path, "mode: read_only\nwrites:\n  max_object_per_change: 5\n"))


def test_bad_cidr_rejected(tmp_path: Path) -> None:
    text = "writes:\n  rules:\n    allow_networks: [10.0.0.0/33]\n"
    with pytest.raises(ConfigError):
        load_policy(write(tmp_path, text))


def test_bad_action_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_policy(write(tmp_path, "writes:\n  rules:\n    actions: [allow]\n"))


def test_write_mode_needs_mcp_host_ips(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mcp_host_ips"):
        load_policy(write(tmp_path, "mode: write\n"))


def test_disabling_anti_lockout_needs_second_switch(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="i_understand_lockout_risk"):
        load_policy(write(tmp_path, "anti_lockout:\n  enabled: false\n"))
    policy = load_policy(
        write(tmp_path, "anti_lockout:\n  enabled: false\n  i_understand_lockout_risk: true\n")
    )
    assert not policy.anti_lockout.enabled


def test_not_yaml_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping"):
        load_policy(write(tmp_path, "- just\n- a list\n"))


def test_summary_has_hash_and_source(tmp_path: Path) -> None:
    path = write(tmp_path, "mode: read_only\n")
    summary = load_policy(path).summary()
    assert summary["policy_file"] == str(path)
    assert len(summary["policy_sha256"]) == 64
    assert Policy().summary()["mode"] == "read_only"
