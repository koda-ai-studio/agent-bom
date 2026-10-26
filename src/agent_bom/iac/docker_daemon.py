"""Docker daemon configuration (``daemon.json``) scanner.

Rules
-----
DOCKERD-001  Remote API on TCP without TLS client verification (critical)
DOCKERD-002  Insecure (plain-HTTP / unverified) registry configured (high)
DOCKERD-003  Inter-container communication not restricted (icc) (medium)
DOCKERD-004  User-namespace remapping not enabled (medium)
DOCKERD-005  live-restore not enabled (low)
DOCKERD-006  no-new-privileges not the daemon default (medium)
DOCKERD-007  Experimental features enabled (low)
DOCKERD-008  Container logging disabled (log-driver none) (medium)

Detection: a file named ``daemon.json`` is a Docker daemon config when its
directory is ``docker`` (``/etc/docker``, rootless ``~/.config/docker``) or
``docker/config`` (Windows ``C:\\ProgramData\\docker\\config``), or when the
operator names the file explicitly. Other ``daemon.json`` files in a tree
belong to unrelated tools and are not parsed. A missing key takes dockerd's
documented default, so ``{}`` reports the defaults that are insecure.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_bom.iac.models import IaCFinding

_MAX_CONFIG_BYTES = 1_000_000
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def is_docker_daemon_config(path: Path, root: Path | None = None) -> bool:
    """``daemon.json`` under a Docker config directory, or the explicitly scanned file."""
    if path.name != "daemon.json":
        return False
    if root is not None and path == root:
        return True
    parent = path.parent
    return parent.name == "docker" or (parent.name == "config" and parent.parent.name == "docker")


def _is_rootless(path: Path) -> bool:
    return path.parent.name == "docker" and path.parent.parent.name == ".config"


def _key_line(lines: list[str], key: str) -> int:
    pattern = re.compile(rf'^\s*"{re.escape(key)}"\s*:')
    return next((index for index, line in enumerate(lines, 1) if pattern.match(line)), 1)


def _is_loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_network(host, strict=False).is_loopback
    except ValueError:
        return False


def _remote_tcp_hosts(hosts: Any) -> list[str]:
    if not isinstance(hosts, list):
        return []
    remote: list[str] = []
    for host in hosts:
        value = str(host).strip()
        if value.lower().startswith("tcp://") and not _is_loopback(urlsplit(value).hostname or "0.0.0.0"):
            remote.append(value)
    return remote


def _registry_host(entry: str) -> str:
    """Host (or CIDR) of an ``insecure-registries`` entry such as ``host:5000``, ``[::1]:5000`` or ``10.0.0.0/8``."""
    if "/" in entry:
        return entry
    if entry.startswith("[") and "]" in entry:
        return entry[1 : entry.index("]")]
    return entry.rsplit(":", 1)[0] if entry.count(":") == 1 else entry


def _insecure_registries(registries: Any) -> list[str]:
    if not isinstance(registries, list):
        return []
    entries = [str(r).strip() for r in registries]
    return [entry for entry in entries if entry and not _is_loopback(_registry_host(entry))]


class _Rules:
    def __init__(self, config: dict[str, Any], lines: list[str], rel_path: str) -> None:
        self.config = config
        self.lines = lines
        self.rel_path = rel_path
        self.findings: list[IaCFinding] = []

    def add(self, rule_id: str, severity: str, title: str, message: str, key: str, compliance: list[str]) -> None:
        self.findings.append(
            IaCFinding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                message=message,
                file_path=self.rel_path,
                line_number=_key_line(self.lines, key),
                category="docker-daemon",
                compliance=compliance,
            )
        )


def _network_rules(rules: _Rules) -> None:
    config = rules.config
    remote = _remote_tcp_hosts(config.get("hosts"))
    if remote and config.get("tlsverify") is not True:
        detail = "TLS is on but clients are not verified" if config.get("tls") is True else "the API is unencrypted and unauthenticated"
        rules.add(
            "DOCKERD-001",
            "critical",
            "Docker API exposed on TCP without TLS client verification",
            f"dockerd listens on {', '.join(remote)} and {detail}; anyone who reaches the port controls the host as root. "
            'Set "tlsverify": true with tlscacert/tlscert/tlskey, or listen only on the unix socket.',
            "hosts",
            ["CIS-Docker-2.7", "NIST-SC-8", "NIST-IA-3"],
        )
    insecure = _insecure_registries(config.get("insecure-registries"))
    if insecure:
        rules.add(
            "DOCKERD-002",
            "high",
            "Insecure registry configured",
            f"insecure-registries lists {', '.join(insecure[:5])}: images from it are pulled over plain HTTP or unverified TLS "
            "and can be swapped in transit. Serve the registry over TLS with a trusted certificate.",
            "insecure-registries",
            ["CIS-Docker-2.5", "NIST-SC-8", "NIST-SI-7"],
        )
    if config.get("icc", True) is not False:
        rules.add(
            "DOCKERD-003",
            "medium",
            "Inter-container communication not restricted",
            'Containers on the default bridge can reach each other on every port. Set "icc": false and link only what must talk.',
            "icc",
            ["CIS-Docker-2.2", "NIST-SC-7"],
        )


def _runtime_rules(rules: _Rules, rootless: bool) -> None:
    config = rules.config
    if not rootless and not str(config.get("userns-remap") or "").strip():
        rules.add(
            "DOCKERD-004",
            "medium",
            "User-namespace remapping not enabled",
            'Root in a container is root on the host. Set "userns-remap": "default" (or run dockerd rootless).',
            "userns-remap",
            ["CIS-Docker-2.9", "NIST-AC-6"],
        )
    if config.get("live-restore") is not True:
        rules.add(
            "DOCKERD-005",
            "low",
            "live-restore not enabled",
            'Restarting or upgrading dockerd stops every container. Set "live-restore": true.',
            "live-restore",
            ["CIS-Docker-2.14", "NIST-CP-10"],
        )
    if config.get("no-new-privileges") is not True:
        rules.add(
            "DOCKERD-006",
            "medium",
            "no-new-privileges is not the daemon default",
            'Containers may gain privileges through setuid binaries unless each one opts out. Set "no-new-privileges": true.',
            "no-new-privileges",
            ["CIS-Docker-2.18", "NIST-AC-6"],
        )
    if config.get("experimental") is True:
        rules.add(
            "DOCKERD-007",
            "low",
            "Experimental daemon features enabled",
            'Experimental features are unsupported and may change or bypass controls. Set "experimental": false in production.',
            "experimental",
            ["CIS-Docker-2.17", "NIST-CM-7"],
        )
    if str(config.get("log-driver", "")).strip().lower() == "none":
        rules.add(
            "DOCKERD-008",
            "medium",
            "Container logging disabled",
            'log-driver "none" discards every container log, leaving no record for incident response. '
            "Use json-file, local, journald or a remote driver.",
            "log-driver",
            ["CIS-Docker-2.13", "NIST-AU-2", "NIST-AU-12"],
        )


def scan_docker_daemon(file_path: str | Path) -> list[IaCFinding]:
    """Scan one Docker daemon configuration file."""
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(config, dict):
        return []
    rules = _Rules(config, text.splitlines(), str(path))
    _network_rules(rules)
    _runtime_rules(rules, _is_rootless(path))
    return rules.findings
