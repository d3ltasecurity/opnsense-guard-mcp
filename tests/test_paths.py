import pytest

from opnsense_guard.client import PathNotAllowed, check_read_path

ALLOWED = [
    "/api/core/firmware/status",
    "/api/diagnostics/system/systemInformation",
    "/api/firewall/filter/searchRule",
    "/api/firewall/alias/searchItem",
    "/api/firewall/filter/getRule/0b1c2d3e-1111-2222-3333-444455556666",
    "/api/ids/settings/get",
    "/api/diagnostics/log/core/system",
    "/api/dnsmasq/leases/search",
    "api/core/firmware/status",  # leading slash added
]


@pytest.mark.parametrize("path", ALLOWED)
def test_allowed(path: str) -> None:
    assert check_read_path(path).startswith("/api/")


DENIED = [
    # mutating verbs, any case
    "/api/core/system/reboot",
    "/api/core/system/halt",
    "/api/core/system/Reboot",
    "/api/core/firmware/upgrade",
    "/api/core/firmware/update",
    "/api/firewall/filter/addRule",
    "/api/firewall/filter/setRule/abc",
    "/api/firewall/filter/delRule/abc",
    "/api/firewall/filter/toggleRule/abc",
    "/api/firewall/filter/apply",
    "/api/firewall/filter/revert",
    "/api/core/service/restart/unbound",
    "/api/ids/service/reconfigure",
    # not under an allowed prefix
    "/api/core/backup/download/this",
    "/api/auth/user/search",
    "/api/openvpn/export/accounts",
    "/index.php",
    "/",
    # smuggling attempts
    "/api/firewall/filter/../../core/system/reboot",
    "/api/firewall/filter/./searchRule",
    "/api/firewall/filter/%2e%2e/x",
    "/api/core/firmware/status?x=1",
    "/api/core/firmware/status#frag",
    "/api/core/firmware\\status",
    "/api//core/firmware/status",
    "/api/core/firmware/stätus",
    "/api/core/firmware/st atus",
]


@pytest.mark.parametrize("path", DENIED)
def test_denied(path: str) -> None:
    with pytest.raises(PathNotAllowed):
        check_read_path(path)
