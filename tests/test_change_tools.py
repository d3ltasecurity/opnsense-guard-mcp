from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import respx
from mcp.server import MCPServer
from pydantic import SecretStr

from conftest import call
from fake_opnsense import FakeOPNsense
from opnsense_guard.audit import AuditLog
from opnsense_guard.client import ReadClient, WriteClient
from opnsense_guard.config import ConfigError, ReadSettings
from opnsense_guard.journal import Journal
from opnsense_guard.policy import Policy, load_policy
from opnsense_guard.server import build_server

ROOT = Path(__file__).resolve().parent.parent
CHANGE_TOOLS = {"change_apply", "change_confirm", "change_rollback", "change_list", "change_get"}
ADD = {
    "op": "add",
    "rule": {
        "action": "block",
        "interface": "opt1",
        "protocol": "TCP",
        "source_net": "192.168.50.0/24",
        "destination_net": "(self)",
        "destination_port": "22",
        "description": "DMZ no SSH",
    },
}


@pytest.fixture
def fw(api: respx.MockRouter) -> FakeOPNsense:
    fake = FakeOPNsense()
    fake.mount(api)
    return fake


@pytest.fixture
async def write_client() -> AsyncIterator[WriteClient]:
    c = WriteClient(
        ReadSettings(url="https://fw.test", api_key=SecretStr("w"), api_secret=SecretStr("s"))
    )
    yield c
    await c.aclose()


def make(
    client: ReadClient,
    tmp_path: Path,
    policy: Policy,
    write: WriteClient | None,
) -> MCPServer:
    return build_server(
        lambda: client,
        policy,
        AuditLog(tmp_path / "audit.jsonl"),
        get_write=(lambda: write) if write else None,
        journal=Journal(tmp_path / "journal.sqlite"),
        timeout_s=30,
    )


@pytest.fixture
def policy() -> Policy:
    return load_policy(ROOT / "policy.example.yaml")


@pytest.fixture
def server(
    client: ReadClient, tmp_path: Path, policy: Policy, write_client: WriteClient
) -> MCPServer:
    return make(client, tmp_path, policy, write_client)


async def names(server: MCPServer) -> set[str]:
    return {t.name for t in await server.list_tools()}


async def test_change_tools_need_write_mode_and_write_client(
    client: ReadClient, tmp_path: Path, policy: Policy, write_client: WriteClient
) -> None:
    assert await names(make(client, tmp_path, policy, write_client)) >= CHANGE_TOOLS
    assert not CHANGE_TOOLS & await names(make(client, tmp_path, policy, None))
    assert not CHANGE_TOOLS & await names(make(client, tmp_path, Policy(), write_client))


async def test_destructive_annotations(server: MCPServer) -> None:
    tools = {t.name: t for t in await server.list_tools()}
    for name in ("change_apply", "change_rollback"):
        assert tools[name].annotations.destructive_hint is True  # type: ignore[union-attr]
    for name in ("change_list", "change_get"):
        assert tools[name].annotations.read_only_hint is True  # type: ignore[union-attr]


async def test_apply_needs_user_confirmation_without_elicitation(
    server: MCPServer, fw: FakeOPNsense
) -> None:
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    first = await call(server, "change_apply", {"plan_id": plan["plan_id"]})
    assert first["status"] == "needs_confirmation"
    assert first["diff"] == plan["diff"]
    assert not fw.rules

    applied = await call(
        server, "change_apply", {"plan_id": plan["plan_id"], "user_confirmed": True}
    )
    assert applied["status"] == "pending", applied
    assert applied["confirm_method"] == "user_confirmed_in_chat"
    assert len(fw.rules) == 1

    listed = (await server.call_tool("change_list", {})).structured_content
    assert listed is not None
    assert listed["result"][0]["id"] == applied["id"]
    assert listed["result"][0]["seconds_left"] > 0

    kept = await call(server, "change_confirm", {"change_id": applied["id"]})
    assert kept["status"] == "confirmed"
    got = await call(server, "change_get", {"change_id": applied["id"]})
    assert got["objects"][0]["after"]["destination_port"] == "22"


async def test_no_confirmation_needed_when_policy_says_so(
    client: ReadClient,
    tmp_path: Path,
    policy: Policy,
    write_client: WriteClient,
    fw: FakeOPNsense,
) -> None:
    writes = policy.writes.model_copy(update={"require_human_confirm": False})
    server = make(client, tmp_path, policy.model_copy(update={"writes": writes}), write_client)
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    applied = await call(server, "change_apply", {"plan_id": plan["plan_id"]})
    assert applied["status"] == "pending"
    assert applied["confirm_method"] == "not_required"


def tool_fn(server: MCPServer, name: str) -> Any:
    return server._tool_manager.get_tool(name).fn  # type: ignore[union-attr]


def fake_ctx(
    scope: str | None = None,
    elicit_answer: Any = None,
    elicit_error: BaseException | None = None,
) -> Any:
    state = {"token_name": "hub", "token_scope": scope} if scope else {}
    request = SimpleNamespace(scope={"state": state}) if scope else None

    async def elicit(message: str, schema: Any) -> Any:
        fake_ctx.last_message = message  # type: ignore[attr-defined]
        if elicit_error is not None:
            raise elicit_error
        return elicit_answer

    declares = elicit_answer is not None or elicit_error is not None
    caps = SimpleNamespace(elicitation=object()) if declares else None
    return SimpleNamespace(
        request_context=SimpleNamespace(request=request),
        client_capabilities=caps,
        elicit=elicit,
    )


async def test_read_token_cannot_apply_or_rollback(server: MCPServer, fw: FakeOPNsense) -> None:
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    ctx = fake_ctx(scope="read")
    result = await tool_fn(server, "change_apply")(plan["plan_id"], ctx, user_confirmed=True)
    assert "scope 'write'" in result["error"]
    result = await tool_fn(server, "change_rollback")("c_x", ctx)
    assert "scope 'write'" in result["error"]
    assert not fw.rules


async def test_elicitation_decline_changes_nothing(server: MCPServer, fw: FakeOPNsense) -> None:
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    declined = SimpleNamespace(action="decline", data=None)
    result = await tool_fn(server, "change_apply")(plan["plan_id"], fake_ctx("write", declined))
    assert result["status"] == "declined"
    assert "[opt1] block in" in fake_ctx.last_message  # type: ignore[attr-defined]
    assert not fw.rules


async def test_elicitation_accept_applies(server: MCPServer, fw: FakeOPNsense) -> None:
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    accepted = SimpleNamespace(action="accept", data=SimpleNamespace(approve=True))
    result = await tool_fn(server, "change_apply")(plan["plan_id"], fake_ctx("write", accepted))
    assert result["status"] == "pending", result
    assert result["confirm_method"] == "elicitation"
    assert result["actor"] == "token:hub"


async def test_elicitation_accept_but_unticked_is_a_no(server: MCPServer, fw: FakeOPNsense) -> None:
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    unticked = SimpleNamespace(action="accept", data=SimpleNamespace(approve=False))
    result = await tool_fn(server, "change_apply")(plan["plan_id"], fake_ctx("write", unticked))
    assert result["status"] == "declined"
    assert not fw.rules


async def test_declared_elicitation_the_transport_cannot_carry_falls_back(
    server: MCPServer, fw: FakeOPNsense
) -> None:
    """A client may declare elicitation on a transport with no back-channel.

    Found on a live HTTPS server: ctx.elicit() raised, the error escaped the
    tool, and user_confirmed could never be reached, so no change could be
    applied at all.
    """
    plan = await call(server, "rule_plan", {"operations": [ADD]})
    boom = RuntimeError(
        "Cannot send 'elicitation/create': this transport context has no "
        "back-channel for server-initiated requests"
    )
    apply = tool_fn(server, "change_apply")

    asked = await apply(plan["plan_id"], fake_ctx("write", elicit_error=boom))
    assert asked["status"] == "needs_confirmation"
    assert asked["diff"] == plan["diff"]
    assert not fw.rules

    applied = await apply(
        plan["plan_id"], fake_ctx("write", elicit_error=boom), user_confirmed=True
    )
    assert applied["status"] == "pending", applied
    assert applied["confirm_method"] == "user_confirmed_in_chat"
    assert len(fw.rules) == 1


def test_write_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from opnsense_guard.client import write_settings_from_env

    monkeypatch.setenv("OPNSENSE_URL", "https://fw.test")
    monkeypatch.setenv("OPNSENSE_API_KEY", "read-key")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "read-secret")
    monkeypatch.delenv("OPNSENSE_WRITE_API_KEY", raising=False)
    monkeypatch.delenv("OPNSENSE_WRITE_API_SECRET", raising=False)
    assert write_settings_from_env() is None

    monkeypatch.setenv("OPNSENSE_WRITE_API_KEY", "write-key")
    with pytest.raises(ConfigError, match="both"):
        write_settings_from_env()

    monkeypatch.setenv("OPNSENSE_WRITE_API_SECRET", "write-secret")
    settings = write_settings_from_env()
    assert settings is not None
    assert settings.api_key.get_secret_value() == "write-key"

    monkeypatch.setenv("OPNSENSE_WRITE_API_KEY", "read-key")
    with pytest.raises(ConfigError, match="different user"):
        write_settings_from_env()
