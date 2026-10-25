"""A small stateful fake of the OPNsense filter + alias API, for respx.

Replies follow the 26.7 shapes (see tests/fixtures/getrule_26_7.json):
option fields as {key: {value, selected}}, missing objects as {}.
Fault hooks let tests break individual steps.
"""

from __future__ import annotations

import copy
import json
import re
import uuid as uuidlib
from collections.abc import Callable
from typing import Any

import httpx
import respx

UUID = r"[0-9a-fA-F-]{36}"
OPTION_FIELDS = {
    "action": ("pass", "block", "reject"),
    "interface": ("opt1", "opt2", "lan", "wan"),
    "direction": ("in", "out", "any"),
    "ipprotocol": ("inet", "inet6", "inet46"),
    "protocol": ("any", "TCP", "UDP", "TCP/UDP", "ICMP"),
}
ALIAS_TYPES = ("host", "network", "port", "url")


def _opts(selected: str, keys: tuple[str, ...]) -> dict[str, Any]:
    chosen = set(selected.split(","))
    return {k: {"value": k, "selected": 1 if k in chosen else 0} for k in keys}


class FakeOPNsense:
    def __init__(self) -> None:
        self.rules: dict[str, dict[str, str]] = {}
        self.aliases: dict[str, dict[str, str]] = {}
        self.applies = 0
        self.writes: list[str] = []
        self.healthy = True
        self.fail: set[str] = set()  # command names to answer with result=failed
        self.fail_once: set[str] = set()  # same, but only the first time
        self.on_write: Callable[[str, dict[str, Any]], None] | None = None
        self.after_add: Callable[[str], None] | None = None  # called with a new rule's uuid

    # ------------------------------------------------------------ seeding

    def add_rule(self, **fields: str) -> str:
        rule = {
            "sequence": str(100 + len(self.rules)),
            "enabled": "1",
            "action": "block",
            "interface": "opt1",
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": "192.168.50.0/24",
            "source_port": "",
            "destination_net": "any",
            "destination_port": "",
            "log": "1",
            "description": "",
            "quick": "1",
            "interfacenot": "0",
            "source_not": "0",
            "destination_not": "0",
            "gateway": "",  # an "advanced" field plans never touch
        }
        rule.update(fields)
        uid = str(uuidlib.uuid4())
        self.rules[uid] = rule
        return uid

    def add_alias(self, name: str, type: str, entries: list[str], description: str = "") -> str:
        uid = str(uuidlib.uuid4())
        self.aliases[uid] = {
            "name": name,
            "type": type,
            "content": "\n".join(entries),
            "description": description,
        }
        return uid

    def alias_by_name(self, name: str) -> dict[str, str] | None:
        return next((a for a in self.aliases.values() if a["name"] == name), None)

    # ---------------------------------------------------------- handlers

    def _json(self, data: Any, status: int = 200) -> httpx.Response:
        return httpx.Response(status, json=data)

    def _body(self, request: httpx.Request) -> dict[str, Any]:
        return json.loads(request.content or b"{}")

    def _write(self, command: str, request: httpx.Request) -> httpx.Response | None:
        self.writes.append(command)
        if self.on_write:
            self.on_write(command, self._body(request))
        if command in self.fail_once:
            self.fail_once.discard(command)
            return self._json({"result": "failed", "validations": {"x": "injected failure"}})
        if command in self.fail:
            return self._json({"result": "failed", "validations": {"x": "injected failure"}})
        return None

    def get_rule(self, request: httpx.Request, uid: str) -> httpx.Response:
        rule = self.rules.get(uid)
        if rule is None:
            return self._json({})
        out: dict[str, Any] = dict(rule)
        for name, keys in OPTION_FIELDS.items():
            out[name] = _opts(rule[name], keys)
        return self._json({"rule": out})

    def add_rule_api(self, request: httpx.Request) -> httpx.Response:
        if (failed := self._write("addRule", request)) is not None:
            return failed
        uid = self.add_rule(**self._body(request)["rule"])
        if self.after_add:
            self.after_add(uid)
        return self._json({"result": "saved", "uuid": uid})

    def set_rule(self, request: httpx.Request, uid: str) -> httpx.Response:
        if (failed := self._write("setRule", request)) is not None:
            return failed
        if uid not in self.rules:
            return self._json({"result": "failed"})
        self.rules[uid].update(self._body(request)["rule"])
        return self._json({"result": "saved"})

    def del_rule(self, request: httpx.Request, uid: str) -> httpx.Response:
        if (failed := self._write("delRule", request)) is not None:
            return failed
        return self._json({"result": "deleted" if self.rules.pop(uid, None) else "not found"})

    def toggle_rule(self, request: httpx.Request, uid: str, value: str) -> httpx.Response:
        if (failed := self._write("toggleRule", request)) is not None:
            return failed
        self.rules[uid]["enabled"] = value
        return self._json({"result": "Enabled" if value == "1" else "Disabled", "changed": True})

    def apply(self, request: httpx.Request) -> httpx.Response:
        if (failed := self._write("apply", request)) is not None:
            return failed
        self.applies += 1
        return self._json({"status": "OK"})

    def alias_uuid(self, request: httpx.Request, name: str) -> httpx.Response:
        for uid, alias in self.aliases.items():
            if alias["name"] == name:
                return self._json({"uuid": uid})
        return self._json({})

    def alias_get(self, request: httpx.Request, uid: str) -> httpx.Response:
        alias = self.aliases.get(uid)
        if alias is None:
            return self._json({})
        entries = [e for e in alias["content"].split("\n") if e]
        return self._json(
            {
                "alias": {
                    "name": alias["name"],
                    "type": _opts(alias["type"], ALIAS_TYPES),
                    "content": {e: {"value": e, "selected": 1} for e in entries},
                    "description": alias["description"],
                }
            }
        )

    def alias_add(self, request: httpx.Request) -> httpx.Response:
        if (failed := self._write("addItem", request)) is not None:
            return failed
        a = self._body(request)["alias"]
        uid = self.add_alias(a["name"], a["type"], a["content"].split("\n"), a["description"])
        return self._json({"result": "saved", "uuid": uid})

    def alias_set(self, request: httpx.Request, uid: str) -> httpx.Response:
        if (failed := self._write("setItem", request)) is not None:
            return failed
        self.aliases[uid].update(self._body(request)["alias"])
        return self._json({"result": "saved"})

    def alias_del(self, request: httpx.Request, uid: str) -> httpx.Response:
        if (failed := self._write("delItem", request)) is not None:
            return failed
        self.aliases.pop(uid, None)
        return self._json({"result": "deleted"})

    def reconfigure(self, request: httpx.Request) -> httpx.Response:
        if (failed := self._write("reconfigure", request)) is not None:
            return failed
        self.applies += 1
        return self._json({"status": "ok"})

    def health(self, request: httpx.Request) -> httpx.Response:
        if not self.healthy:
            raise httpx.ConnectError("firewall unreachable (simulated lockout)")
        return self._json({"product_version": "26.7.4"})

    # -------------------------------------------------------------- mount

    def mount(self, router: respx.MockRouter) -> None:
        def route(method: str, pattern: str, handler: Callable[..., httpx.Response]) -> None:
            regex = re.compile(r"^https://fw\.test" + pattern + r"$")
            router.route(method=method, url__regex=regex).mock(
                side_effect=lambda request, **kw: handler(request, **kw)
            )

        f = "/api/firewall/filter"
        a = "/api/firewall/alias"
        route("GET", rf"{f}/getRule/(?P<uid>{UUID})", self.get_rule)
        route("POST", rf"{f}/addRule", self.add_rule_api)
        route("POST", rf"{f}/setRule/(?P<uid>{UUID})", self.set_rule)
        route("POST", rf"{f}/delRule/(?P<uid>{UUID})", self.del_rule)
        route("POST", rf"{f}/toggleRule/(?P<uid>{UUID})/(?P<value>[01])", self.toggle_rule)
        route("POST", rf"{f}/apply", self.apply)
        route("GET", rf"{a}/getAliasUUID/(?P<name>\w+)", self.alias_uuid)
        route("GET", rf"{a}/getItem/(?P<uid>{UUID})", self.alias_get)
        route("POST", rf"{a}/addItem", self.alias_add)
        route("POST", rf"{a}/setItem/(?P<uid>{UUID})", self.alias_set)
        route("POST", rf"{a}/delItem/(?P<uid>{UUID})", self.alias_del)
        route("POST", rf"{a}/reconfigure", self.reconfigure)
        route("GET", r"/api/core/firmware/status", self.health)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy({"rules": self.rules, "aliases": self.aliases})
