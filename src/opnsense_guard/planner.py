"""Plans: describe a change, check it against policy, show a diff.

Planning never writes to the firewall. It reads the current state of every
object a plan touches, computes the after-state, runs every policy check and
returns the result. Plans are kept in memory for a short time so a later
phase can apply exactly what was shown, after re-checking it.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from opnsense_guard.client import OPNsenseError, ReadClient
from opnsense_guard.policy import IPAddress, IPNetwork, Policy

PLAN_TTL_S = 900
MAX_PLANS = 200

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ALIAS_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,31}$")
PORT_RE = re.compile(r"^(\d{1,5})(?:[-:](\d{1,5}))?$")

RULE_FIELDS = (
    "sequence",  # evaluation order: first match wins, lower sequence first
    "enabled",
    "action",
    "interface",
    "direction",
    "ipprotocol",
    "protocol",
    "source_net",
    "source_port",
    "destination_net",
    "destination_port",
    "log",
    "description",
    # Not settable through plans. New rules get the safe values below; existing
    # rules with anything else are refused, because the checks above would
    # misjudge them (a negated source matches everything *except* that net).
    "quick",
    "interfacenot",
    "source_not",
    "destination_not",
)
FIXED_RULE_FIELDS = {"quick": "1", "interfacenot": "0", "source_not": "0", "destination_not": "0"}

# --------------------------------------------------------------- models


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuleSpec(_Strict):
    """A filter rule, in the field names the OPNsense API uses."""

    action: Literal["pass", "block", "reject"]
    interface: str = Field(min_length=1, max_length=64)
    direction: Literal["in", "out"] = "in"
    ipprotocol: Literal["inet", "inet6", "inet46"] = "inet"
    protocol: Literal["any", "TCP", "UDP", "TCP/UDP", "ICMP"] = "any"
    source_net: str = Field(default="any", min_length=1, max_length=512)
    source_port: str = Field(default="", max_length=64)
    destination_net: str = Field(default="any", min_length=1, max_length=512)
    destination_port: str = Field(default="", max_length=64)
    log: bool = True
    enabled: bool = True
    description: str = Field(default="", max_length=200)
    sequence: int | None = Field(
        default=None,
        ge=1,
        le=999999,
        description="Evaluation order (lower first). Omit to let OPNsense choose.",
    )


class RuleChanges(_Strict):
    """Fields to change on an existing rule. Omitted fields stay as they are."""

    action: Literal["pass", "block", "reject"] | None = None
    interface: str | None = Field(default=None, min_length=1, max_length=64)
    direction: Literal["in", "out"] | None = None
    ipprotocol: Literal["inet", "inet6", "inet46"] | None = None
    protocol: Literal["any", "TCP", "UDP", "TCP/UDP", "ICMP"] | None = None
    source_net: str | None = Field(default=None, min_length=1, max_length=512)
    source_port: str | None = Field(default=None, max_length=64)
    destination_net: str | None = Field(default=None, min_length=1, max_length=512)
    destination_port: str | None = Field(default=None, max_length=64)
    log: bool | None = None
    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=200)
    sequence: int | None = Field(default=None, ge=1, le=999999)


class RuleOp(_Strict):
    op: Literal["add", "update", "delete", "toggle"]
    uuid: str | None = None
    rule: RuleSpec | None = None
    changes: RuleChanges | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def _shape(self) -> RuleOp:
        if self.op == "add":
            if self.rule is None or self.uuid or self.changes:
                raise ValueError("add needs 'rule' (and no uuid/changes)")
        else:
            if not self.uuid or not UUID_RE.match(self.uuid):
                raise ValueError(f"{self.op} needs a valid 'uuid'")
            if self.op == "update" and self.changes is None:
                raise ValueError("update needs 'changes'")
            if self.op == "toggle" and self.enabled is None:
                raise ValueError("toggle needs 'enabled' (true/false)")
        return self


class AliasOp(_Strict):
    op: Literal["create", "add_entries", "remove_entries", "delete"]
    name: str = Field(min_length=1, max_length=31)
    type: Literal["host", "network", "port"] | None = None
    entries: list[str] = Field(default_factory=list, max_length=4096)
    description: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def _shape(self) -> AliasOp:
        if not ALIAS_NAME_RE.match(self.name):
            raise ValueError("alias name: letters, digits and _ only, max 31 chars")
        if self.op == "create" and self.type is None:
            raise ValueError("create needs 'type'")
        if self.op in ("add_entries", "remove_entries") and not self.entries:
            raise ValueError(f"{self.op} needs 'entries'")
        return self


@dataclass
class PlannedObject:
    type: Literal["rule", "alias"]
    op: str
    ref: str  # rule uuid, alias name, or "(new)"
    before: dict[str, str] | None
    after: dict[str, str] | None
    diff: list[str]
    violations: list[str] = field(default_factory=list)


@dataclass
class Plan:
    id: str
    kind: Literal["rule", "alias"]
    actor: str
    created: float
    objects: list[PlannedObject]
    violations: list[str]
    policy_sha256: str

    @property
    def allowed(self) -> bool:
        return not self.violations and not any(o.violations for o in self.objects)

    @property
    def expires(self) -> float:
        return self.created + PLAN_TTL_S

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.id,
            "kind": self.kind,
            "status": "allowed" if self.allowed else "denied",
            "actor": self.actor,
            "created": _iso(self.created),
            "expires": _iso(self.expires),
            "policy_sha256": self.policy_sha256,
            "violations": self.violations + [v for o in self.objects for v in o.violations],
            "diff": [line for o in self.objects for line in o.diff],
            "objects": [
                {
                    "type": o.type,
                    "op": o.op,
                    "ref": o.ref,
                    "before": o.before,
                    "after": o.after,
                    "violations": o.violations,
                }
                for o in self.objects
            ],
            "note": "Planning only. Nothing was changed on the firewall.",
        }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


class PlanStore:
    """Short-lived in-memory plan store."""

    def __init__(self) -> None:
        self._plans: dict[str, Plan] = {}

    def add(self, plan: Plan) -> None:
        self._purge()
        if len(self._plans) >= MAX_PLANS:
            oldest = min(self._plans.values(), key=lambda p: p.created)
            del self._plans[oldest.id]
        self._plans[plan.id] = plan

    def get(self, plan_id: str) -> Plan | None:
        self._purge()
        return self._plans.get(plan_id)

    def _purge(self) -> None:
        now = time.time()
        for pid in [p.id for p in self._plans.values() if p.expires < now]:
            del self._plans[pid]


# --------------------------------------------------------- normalising


def flatten(value: Any) -> str:
    """OPNsense returns option fields as {key: {value, selected}}; keep the selected keys."""
    if isinstance(value, dict):
        if all(isinstance(v, dict) and "selected" in v for v in value.values()):
            return ",".join(k for k, v in value.items() if str(v.get("selected")) in ("1", "True"))
        return ",".join(str(v) for v in value.values())
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return ""
    return str(value)


def alias_view(a: dict[str, Any] | None) -> dict[str, str] | None:
    """Flat alias state for plans, diffs and the journal (uuid kept when known)."""
    if a is None:
        return None
    out = {
        "type": a["type"],
        "entries": ",".join(a["entries"]),
        "description": a["description"],
    }
    if a.get("uuid"):
        out["uuid"] = a["uuid"]
    return out


ALIAS_FIELDS = ("type", "entries", "description")


def normalise_rule(raw: dict[str, Any]) -> dict[str, str]:
    return {name: flatten(raw.get(name, "")) for name in RULE_FIELDS}


def spec_to_fields(spec: RuleSpec) -> dict[str, str]:
    data = {**spec.model_dump(), **FIXED_RULE_FIELDS}
    return {name: flatten(data[name]) for name in RULE_FIELDS}


def describe_rule(r: dict[str, str]) -> str:
    seq = f"#{r['sequence']} " if r.get("sequence") else "#(auto) "
    port = f" port {r['destination_port']}" if r.get("destination_port") else ""
    sport = f" port {r['source_port']}" if r.get("source_port") else ""
    flags = []
    if r.get("log") == "1":
        flags.append("log")
    if r.get("enabled") == "0":
        flags.append("DISABLED")
    flag_text = f" [{', '.join(flags)}]" if flags else ""
    return seq + (
        f"[{r.get('interface')}] {r.get('action')} {r.get('direction')} {r.get('ipprotocol')} "
        f"{r.get('protocol')} from {r.get('source_net')}{sport} to "
        f"{r.get('destination_net')}{port}{flag_text} '{r.get('description')}'"
    )


def field_diff(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return [
        f"    {name}: {before.get(name, '')!r} -> {after.get(name, '')!r}"
        for name in RULE_FIELDS
        if before.get(name, "") != after.get(name, "")
    ]


# ------------------------------------------------------- policy checks


def _parse_net(value: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _inside(net: IPNetwork, allowed: list[IPNetwork]) -> bool:
    return any(net.version == a.version and net.subnet_of(a) for a in allowed)  # type: ignore[arg-type]


def _contains_any(net: IPNetwork, ips: list[IPAddress]) -> bool:
    return any(ip.version == net.version and ip in net for ip in ips)


class PolicyChecker:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.w = policy.writes
        self.rules = policy.writes.rules
        self.nets = policy.writes.rules.networks()
        self.lock = policy.anti_lockout
        self.mcp_ips = policy.anti_lockout.host_ips()

    def tagged(self, description: str) -> str:
        tag = self.w.tag
        return description if description.startswith(tag) else f"{tag} {description}".strip()

    def _iface_token(self, token: str) -> str | None:
        """'opt1' or 'opt1ip' -> 'opt1' if it names an allowed interface."""
        base = token[:-2] if token.endswith("ip") else token
        return base if base in self.rules.interfaces else None

    def check_net(self, side: str, value: str) -> list[str]:
        problems = []
        for item in (v.strip() for v in value.split(",")):
            if item in ("any", "(self)"):
                continue
            if self._iface_token(item):
                continue
            if item.startswith(self.w.aliases.name_prefix):
                continue
            net = _parse_net(item)
            if net is None:
                problems.append(
                    f"{side} '{item}' is not an allowed interface token, "
                    f"'{self.w.aliases.name_prefix}' alias, IP or CIDR"
                )
            elif not _inside(net, self.nets):
                problems.append(f"{side} {item} is outside allow_networks")
        return problems

    def check_port(self, side: str, value: str) -> list[str]:
        if value in ("", "any") or value.startswith(self.w.aliases.name_prefix):
            return []
        match = PORT_RE.match(value)
        if not match:
            return [f"{side} '{value}' must be a port, a range a-b, or an alias"]
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if not (1 <= low <= high <= 65535):
            return [f"{side} '{value}' is out of range"]
        return []

    def source_hits_mcp_host(self, source: str) -> bool:
        for item in (v.strip() for v in source.split(",")):
            if item == "any":
                return True
            base = item[:-2] if item.endswith("ip") else item
            if base in self.lock.protected_interfaces:
                return True
            net = _parse_net(item)
            if net is not None and _contains_any(net, self.mcp_ips):
                return True
        return False

    def check_rule(
        self, op: str, before: dict[str, str] | None, after: dict[str, str] | None, uuid: str
    ) -> list[str]:
        v: list[str] = []
        if uuid and uuid in self.rules.protect_uuids:
            v.append(f"rule {uuid} is protected by policy (protect_uuids)")
        own = before is None or before.get("description", "").startswith(self.w.tag)
        if self.w.only_modify_own and not own:
            v.append(
                f"rule {uuid} was not created by this server (no '{self.w.tag}' tag) "
                "and only_modify_own is on"
            )

        for state in (before, after):
            if state is None:
                continue
            negated = [
                f for f in ("interfacenot", "source_not", "destination_not") if state[f] == "1"
            ]
            if negated:
                v.append(
                    f"rule uses negation ({', '.join(negated)}); this server does not "
                    "plan changes to negated rules"
                )
                break
            if state["quick"] != "1":
                v.append("rule is not 'quick' (last-match); only first-match rules are supported")
                break

        # Anti-lockout: protected interfaces accept new pass rules only.
        new_pass = op == "add" and after is not None and after.get("action") == "pass"
        if self.lock.enabled and not new_pass:
            for state in (before, after):
                if state and state.get("interface") in self.lock.protected_interfaces:
                    v.append(
                        f"interface {state['interface']} carries this server's API access "
                        "(anti_lockout.protected_interfaces): only new pass rules allowed"
                    )
                    break

        if after is None:  # delete
            return v

        iface = after["interface"]
        if "," in iface and self.rules.forbid.floating_rules:
            v.append("rules on several interfaces (floating) are forbidden by policy")
        for name in iface.split(","):
            if name not in self.rules.interfaces:
                v.append(f"interface '{name}' is not in the allowed interfaces")
        if after["action"] not in self.rules.actions:
            v.append(f"action '{after['action']}' is not allowed")
        if after["direction"] not in self.rules.directions:
            v.append(f"direction '{after['direction']}' is not allowed")
        v += self.check_net("source", after["source_net"])
        v += self.check_net("destination", after["destination_net"])
        v += self.check_port("source port", after["source_port"])
        v += self.check_port("destination port", after["destination_port"])

        forbid = self.rules.forbid
        if (
            forbid.any_to_any_pass
            and after["action"] == "pass"
            and after["source_net"] == "any"
            and after["destination_net"] == "any"
        ):
            v.append("any -> any pass rules are forbidden")
        if (
            forbid.wan_inbound_pass
            and "wan" in iface.split(",")
            and after["action"] == "pass"
            and after["direction"] == "in"
        ):
            v.append("inbound pass rules on WAN are forbidden")
        if forbid.disable_logging and after["log"] != "1":
            v.append("every rule written by this server must have logging on")
        if not after["description"].startswith(self.w.tag):
            v.append(f"description must start with '{self.w.tag}'")

        if (
            self.lock.enabled
            and after["action"] in ("block", "reject")
            and self.source_hits_mcp_host(after["source_net"])
        ):
            v.append(
                "this block/reject rule could match this server's own address "
                "(anti_lockout.mcp_host_ips) and cut off its API access"
            )
        return v

    def check_alias_entries(self, alias_type: str, entries: list[str]) -> list[str]:
        v = []
        for entry in entries:
            if alias_type == "port":
                v += self.check_port("alias entry", entry)
                continue
            net = _parse_net(entry)
            if net is None:
                v.append(f"alias entry '{entry}' must be an IP or CIDR (hostnames not allowed)")
                continue
            if alias_type == "host" and net.num_addresses != 1:
                v.append(f"host alias entry '{entry}' must be a single address")
            if not _inside(net, self.nets):
                v.append(f"alias entry {entry} is outside allow_networks")
            if self.lock.enabled and _contains_any(net, self.mcp_ips):
                v.append(
                    f"alias entry {entry} contains this server's own address "
                    "(anti_lockout.mcp_host_ips)"
                )
        return v


# --------------------------------------------------------------- planner


class Planner:
    def __init__(
        self, policy: Policy, get_client: Callable[[], ReadClient], store: PlanStore
    ) -> None:
        self.policy = policy
        self.get_client = get_client
        self.store = store
        self.check = PolicyChecker(policy)

    def _new_plan(self, kind: Literal["rule", "alias"], actor: str, count: int) -> Plan:
        violations = []
        if not self.policy.writable:
            violations.append("policy mode is read_only: no changes can be planned")
        if count > self.policy.writes.max_objects_per_change:
            violations.append(
                f"{count} objects in one change; policy max_objects_per_change is "
                f"{self.policy.writes.max_objects_per_change}"
            )
        if count == 0:
            violations.append("no operations given")
        return Plan(
            id="p_" + secrets.token_hex(8),
            kind=kind,
            actor=actor,
            created=time.time(),
            objects=[],
            violations=violations,
            policy_sha256=self.policy.sha256,
        )

    async def get_rule(self, uuid: str) -> tuple[dict[str, str] | None, str | None]:
        try:
            data = await self.get_client().get(f"/api/firewall/filter/getRule/{uuid}")
        except OPNsenseError as exc:
            return None, f"could not read rule {uuid}: {exc}"
        raw = data.get("rule") if isinstance(data, dict) else None
        if not isinstance(raw, dict) or not raw:
            return None, f"rule {uuid} not found"
        return normalise_rule(raw), None

    async def plan_rules(self, ops: list[RuleOp], actor: str) -> Plan:
        plan = self._new_plan("rule", actor, len(ops))
        for op in ops:
            plan.objects.append(await self._plan_rule(op))
        self.store.add(plan)
        return plan

    async def _plan_rule(self, op: RuleOp) -> PlannedObject:
        if op.op == "add":
            assert op.rule is not None
            after = spec_to_fields(op.rule)
            after["description"] = self.check.tagged(after["description"])
            obj = PlannedObject("rule", "add", "(new)", None, after, [f"+ {describe_rule(after)}"])
            obj.violations = self.check.check_rule("add", None, after, "")
            return obj

        uuid = op.uuid or ""
        before, error = await self.get_rule(uuid)
        if before is None:
            return PlannedObject("rule", op.op, uuid, None, None, [], [error or "unknown error"])

        if op.op == "delete":
            obj = PlannedObject(
                "rule", "delete", uuid, before, None, [f"- {describe_rule(before)}"]
            )
            obj.violations = self.check.check_rule("delete", before, None, uuid)
            return obj

        after = dict(before)
        if op.op == "toggle":
            after["enabled"] = "1" if op.enabled else "0"
        else:
            assert op.changes is not None
            changes = op.changes.model_dump(exclude_none=True)
            after.update({k: flatten(v) for k, v in changes.items()})
            after["description"] = self.check.tagged(after["description"])
        diff = [f"~ {describe_rule(before)}", *field_diff(before, after)]
        if len(diff) == 1:
            diff.append("    (no change)")
        obj = PlannedObject("rule", op.op, uuid, before, after, diff)
        obj.violations = self.check.check_rule(op.op, before, after, uuid)
        return obj

    async def get_alias(self, name: str) -> tuple[dict[str, Any] | None, str | None]:
        """Return ({uuid,type,entries,description}, None), (None, None) if absent, or error."""
        try:
            found = await self.get_client().get(f"/api/firewall/alias/getAliasUUID/{name}")
            uuid = found.get("uuid") if isinstance(found, dict) else None
            if not uuid:
                return None, None
            data = await self.get_client().get(f"/api/firewall/alias/getItem/{uuid}")
        except OPNsenseError as exc:
            if str(exc).startswith("404"):
                return None, None
            return None, f"could not read alias {name}: {exc}"
        raw = data.get("alias") if isinstance(data, dict) else None
        if not isinstance(raw, dict):
            return None, f"alias {name}: unexpected response"
        content = flatten(raw.get("content", ""))
        entries = [e for e in re.split(r"[,\n]", content) if e.strip()]
        return {
            "uuid": uuid,
            "type": flatten(raw.get("type", "")),
            "entries": entries,
            "description": flatten(raw.get("description", "")),
        }, None

    async def plan_aliases(self, ops: list[AliasOp], actor: str) -> Plan:
        plan = self._new_plan("alias", actor, len(ops))
        for op in ops:
            plan.objects.append(await self._plan_alias(op))
        self.store.add(plan)
        return plan

    async def _plan_alias(self, op: AliasOp) -> PlannedObject:
        ap = self.policy.writes.aliases
        v: list[str] = []
        if not op.name.startswith(ap.name_prefix):
            # Out of bounds: do not even look it up.
            violation = f"alias name must start with '{ap.name_prefix}'"
            return PlannedObject("alias", op.op, op.name, None, None, [], [violation])

        current, error = await self.get_alias(op.name)
        if error:
            return PlannedObject("alias", op.op, op.name, None, None, [], [*v, error])

        if op.op == "create":
            if current is not None:
                v.append(f"alias {op.name} already exists")
            alias_type = op.type or ""
            if alias_type not in ap.types:
                v.append(f"alias type '{alias_type}' is not allowed")
            entries = list(dict.fromkeys(op.entries))
            after = {
                "type": alias_type,
                "entries": entries,
                "description": self.check.tagged(op.description),
            }
            v += self.check.check_alias_entries(alias_type, entries)
            if len(entries) > ap.max_entries:
                v.append(f"{len(entries)} entries; policy max_entries is {ap.max_entries}")
            diff = [f"+ alias {op.name} ({alias_type}): {', '.join(entries) or '(empty)'}"]
            return PlannedObject("alias", "create", op.name, None, alias_view(after), diff, v)

        if current is None:
            return PlannedObject("alias", op.op, op.name, None, None, [], [*v, "alias not found"])

        if op.op == "delete":
            diff = [f"- alias {op.name} ({current['type']}): {', '.join(current['entries'])}"]
            return PlannedObject("alias", "delete", op.name, alias_view(current), None, diff, v)

        entries = list(current["entries"])
        if op.op == "add_entries":
            new = [e for e in op.entries if e not in entries]
            v += self.check.check_alias_entries(current["type"], new)
            entries += new
            diff = [f"~ alias {op.name}: + {', '.join(new) or '(nothing new)'}"]
        else:
            gone = [e for e in op.entries if e in entries]
            entries = [e for e in entries if e not in gone]
            diff = [f"~ alias {op.name}: - {', '.join(gone) or '(none present)'}"]
        if len(entries) > ap.max_entries:
            v.append(f"{len(entries)} entries; policy max_entries is {ap.max_entries}")
        after = {**current, "entries": entries}
        return PlannedObject(
            "alias", op.op, op.name, alias_view(current), alias_view(after), diff, v
        )
