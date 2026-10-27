"""DOCKERD-001..008: Docker daemon configuration (daemon.json)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.iac import is_iac_file, scan_iac_with_context
from agent_bom.iac.docker_daemon import scan_docker_daemon

_HARDENED = {
    "icc": False,
    "userns-remap": "default",
    "live-restore": True,
    "no-new-privileges": True,
    "log-driver": "json-file",
}


def _write(tmp_path: Path, config: dict | str, parent: str = "docker") -> Path:
    directory = tmp_path / parent
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "daemon.json"
    path.write_text(config if isinstance(config, str) else json.dumps(config, indent=2))
    return path


def _ids(path: Path) -> dict[str, int]:
    return {f.rule_id: f.line_number for f in scan_docker_daemon(path)}


def test_hardened_config_is_clean(tmp_path: Path) -> None:
    config = {**_HARDENED, "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"], "tls": True, "tlsverify": True}
    assert _ids(_write(tmp_path, config)) == {}


class TestRemoteApi:
    def test_tcp_without_tls_is_critical_at_the_hosts_line(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {**_HARDENED, "hosts": ["tcp://0.0.0.0:2375"]})
        finding = next(f for f in scan_docker_daemon(path) if f.rule_id == "DOCKERD-001")
        assert finding.severity == "critical"
        assert finding.line_number == path.read_text().splitlines().index('  "hosts": [') + 1

    def test_tls_without_client_verification_is_still_flagged(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {**_HARDENED, "hosts": ["tcp://10.0.0.5:2376"], "tls": True})
        assert "DOCKERD-001" in _ids(path)

    def test_loopback_and_unix_sockets_are_not_remote(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {**_HARDENED, "hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", "fd://"]})
        assert "DOCKERD-001" not in _ids(path)


class TestDaemonDefaults:
    def test_insecure_registry_is_flagged_but_loopback_is_not(self, tmp_path: Path) -> None:
        assert "DOCKERD-002" in _ids(_write(tmp_path, {**_HARDENED, "insecure-registries": ["registry.internal:5000"]}))
        assert "DOCKERD-002" not in _ids(_write(tmp_path, {**_HARDENED, "insecure-registries": ["127.0.0.0/8", "localhost:5000"]}))

    @pytest.mark.parametrize(
        ("key", "value", "rule"),
        [
            ("icc", True, "DOCKERD-003"),
            ("userns-remap", "", "DOCKERD-004"),
            ("live-restore", False, "DOCKERD-005"),
            ("no-new-privileges", False, "DOCKERD-006"),
            ("experimental", True, "DOCKERD-007"),
            ("log-driver", "none", "DOCKERD-008"),
        ],
    )
    def test_each_weak_setting_is_flagged(self, tmp_path: Path, key: str, value: object, rule: str) -> None:
        assert rule in _ids(_write(tmp_path, {**_HARDENED, key: value}))

    @pytest.mark.parametrize(
        ("key", "rule"), [("icc", "DOCKERD-003"), ("userns-remap", "DOCKERD-004"), ("no-new-privileges", "DOCKERD-006")]
    )
    def test_missing_setting_takes_the_insecure_default(self, tmp_path: Path, key: str, rule: str) -> None:
        config = {k: v for k, v in _HARDENED.items() if k != key}
        assert _ids(_write(tmp_path, config))[rule] == 1

    def test_rootless_config_does_not_need_userns_remap(self, tmp_path: Path) -> None:
        config = {k: v for k, v in _HARDENED.items() if k != "userns-remap"}
        assert "DOCKERD-004" not in _ids(_write(tmp_path, config, parent=".config/docker"))


class TestDetection:
    def test_daemon_json_under_a_docker_directory_is_scanned(self, tmp_path: Path) -> None:
        _write(tmp_path / "etc", {**_HARDENED, "icc": True})
        result = scan_iac_with_context(tmp_path)
        assert [f.rule_id for f in result.findings] == ["DOCKERD-003"]
        assert result.findings[0].category == "docker-daemon"
        assert next(v for v in result.verdicts if v.scanner_id == "docker-daemon").files_scanned == 1

    def test_daemon_json_elsewhere_is_not_parsed_in_a_walk(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {"icc": True}, parent="app/config")
        assert scan_iac_with_context(tmp_path).findings == []
        assert is_iac_file(path) is False

    def test_explicitly_named_daemon_json_is_scanned_anywhere(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {**_HARDENED, "experimental": True}, parent="ops")
        assert [f.rule_id for f in scan_iac_with_context(path).findings] == ["DOCKERD-007"]

    def test_malformed_or_non_object_json_yields_no_findings(self, tmp_path: Path) -> None:
        assert scan_docker_daemon(_write(tmp_path, "{not json")) == []
        assert scan_docker_daemon(_write(tmp_path, "[1, 2]")) == []
