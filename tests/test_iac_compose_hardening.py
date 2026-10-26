"""COMPOSE-005 escape capabilities and COMPOSE-007..011 service hardening."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.compose import scan_compose

_HARDENED = "    security_opt:\n      - no-new-privileges:true\n"


@pytest.fixture()
def scan(tmp_path: Path):
    def _scan(service_body: str, hardened: bool = True) -> list[tuple[str, int]]:
        path = tmp_path / "compose.yaml"
        path.write_text("services:\n  app:\n    image: busybox:1.36\n" + service_body + (_HARDENED if hardened else ""))
        return [(f.rule_id, f.line_number) for f in scan_compose(path)]

    return _scan


def _lines(found: list[tuple[str, int]], rule: str) -> list[int]:
    return [line for rule_id, line in found if rule_id == rule]


def _indent(text: str) -> str:
    return "".join("    " + line + "\n" for line in text.splitlines())


class TestEscapeCapabilities:
    @pytest.mark.parametrize("cap", ["SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "CAP_SYS_RAWIO"])
    def test_container_escape_capabilities_are_flagged(self, scan, cap: str) -> None:
        assert _lines(scan(_indent(f"cap_add:\n  - {cap}")), "COMPOSE-005") == [5]

    def test_narrow_capabilities_are_not_flagged(self, scan) -> None:
        assert _lines(scan(_indent("cap_add:\n  - NET_BIND_SERVICE\n  - CHOWN")), "COMPOSE-005") == []


class TestSecurityOpt:
    @pytest.mark.parametrize(
        "opt",
        ["seccomp:unconfined", "seccomp=unconfined", "apparmor:unconfined", "apparmor=unconfined", "label:disable"],
    )
    def test_disabled_confinement_is_flagged_at_the_item(self, scan, opt: str) -> None:
        found = scan(_indent(f"security_opt:\n  - {opt}\n  - no-new-privileges:true"), hardened=False)
        assert _lines(found, "COMPOSE-007") == [5]

    def test_custom_profiles_are_not_unconfined(self, scan) -> None:
        body = _indent("security_opt:\n  - seccomp:./seccomp.json\n  - apparmor:docker-default\n  - no-new-privileges:true")
        assert _lines(scan(body, hardened=False), "COMPOSE-007") == []


class TestHostNamespaces:
    def test_ipc_and_userns_host_are_high_and_uts_is_medium(self, tmp_path: Path) -> None:
        path = tmp_path / "compose.yaml"
        path.write_text("services:\n  app:\n    image: busybox:1.36\n    ipc: host\n    uts: host\n    userns_mode: host\n" + _HARDENED)
        found = {(f.line_number, f.severity) for f in scan_compose(path) if f.rule_id == "COMPOSE-008"}
        assert found == {(4, "high"), (5, "medium"), (6, "high")}

    def test_shareable_and_service_ipc_are_not_host(self, scan) -> None:
        assert _lines(scan(_indent("ipc: shareable\nuts: ''")), "COMPOSE-008") == []


class TestSensitiveHostMounts:
    @pytest.mark.parametrize(
        "volume",
        [
            "/:/host",
            "/etc:/host/etc:ro",
            "/proc:/host/proc",
            "/var/lib/docker:/docker",
            "~/.ssh:/root/.ssh:ro",
            "/etc/shadow:/etc/shadow:ro",
        ],
    )
    def test_sensitive_host_paths_are_flagged(self, scan, volume: str) -> None:
        assert _lines(scan(_indent(f'volumes:\n  - "{volume}"')), "COMPOSE-009") == [5]

    def test_long_syntax_bind_is_flagged(self, scan) -> None:
        body = _indent("volumes:\n  - type: bind\n    source: /sys\n    target: /host/sys")
        assert _lines(scan(body), "COMPOSE-009") == [5]

    @pytest.mark.parametrize(
        "volume",
        [
            "/etc/localtime:/etc/localtime:ro",
            "./data:/data",
            "pgdata:/var/lib/postgresql/data",
            "/srv/app:/app",
            "/var/run/docker.sock:/var/run/docker.sock",
        ],
    )
    def test_ordinary_mounts_are_not_flagged(self, scan, volume: str) -> None:
        assert _lines(scan(_indent(f'volumes:\n  - "{volume}"')), "COMPOSE-009") == []


class TestRootUser:
    @pytest.mark.parametrize("user", ["root", "'0'", "0:0", "root:root"])
    def test_root_user_is_flagged(self, scan, user: str) -> None:
        assert _lines(scan(_indent(f"user: {user}")), "COMPOSE-010") == [4]

    @pytest.mark.parametrize("user", ['"1000:1000"', "app", "'10001'", '"${UID}:${GID}"'])
    def test_non_root_user_is_not_flagged(self, scan, user: str) -> None:
        assert _lines(scan(_indent(f"user: {user}")), "COMPOSE-010") == []


class TestNoNewPrivileges:
    def test_missing_no_new_privileges_is_flagged_at_the_service(self, scan) -> None:
        assert _lines(scan("", hardened=False), "COMPOSE-011") == [2]

    @pytest.mark.parametrize("opt", ["no-new-privileges:true", "no-new-privileges=true", "no-new-privileges"])
    def test_any_spelling_of_the_option_satisfies_it(self, scan, opt: str) -> None:
        assert _lines(scan(_indent(f"security_opt:\n  - {opt}"), hardened=False), "COMPOSE-011") == []

    def test_explicit_false_is_flagged(self, scan) -> None:
        assert _lines(scan(_indent("security_opt:\n  - no-new-privileges:false"), hardened=False), "COMPOSE-011") == [2]

    def test_privileged_service_reports_privileged_not_this(self, scan) -> None:
        assert _lines(scan(_indent("privileged: true"), hardened=False), "COMPOSE-011") == []


def test_compose_rules_do_not_apply_to_kubernetes_yaml(tmp_path: Path) -> None:
    manifest = tmp_path / "deploy.yaml"
    manifest.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: x:1\n")
    assert not any(f.rule_id.startswith("COMPOSE-") for f in scan_iac_with_context(tmp_path).findings)
