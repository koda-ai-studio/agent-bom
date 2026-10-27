"""Docker Compose misconfiguration scanner.

Rules
-----
COMPOSE-001  Service runs privileged (critical)
COMPOSE-002  Service mounts the Docker socket (critical)
COMPOSE-003  Service shares the host network namespace (high)
COMPOSE-004  Service shares the host PID namespace (high)
COMPOSE-005  Service adds ALL, SYS_ADMIN or another container-escape capability (high)
COMPOSE-006  Hardcoded secret in service environment (critical)
COMPOSE-007  security_opt disables seccomp, AppArmor or SELinux (high)
COMPOSE-008  Service shares the host IPC / user namespace (high) or UTS namespace (medium)
COMPOSE-009  Service bind-mounts a sensitive host path (high)
COMPOSE-010  Service runs as root via user: (high)
COMPOSE-011  Service does not set no-new-privileges (low)

Severities mirror the equivalent Kubernetes and Dockerfile rules. Secret
findings name the variable only; the value is never copied into a finding.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.iac.compose_hardening import hardening_findings
from agent_bom.iac.dockerfile_rules import is_hardcoded_secret
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.yaml_lines import item_line, key_line, safe_load_with_lines

_COMPOSE_NAME_RE = re.compile(r"^(?:docker-)?compose(?:[.-][A-Za-z0-9_.-]+)?\.ya?ml$", re.IGNORECASE)
_DOCKER_SOCKET_RE = re.compile(r"(?:^|[:/])(?:var/)?run/docker\.sock(?::|$)")
_ESCAPE_CAPS = ("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "SYS_BOOT", "BPF")
_DANGEROUS_CAPS = frozenset(_ESCAPE_CAPS + tuple(f"CAP_{cap}" for cap in _ESCAPE_CAPS))


def is_compose_file(path: Path) -> bool:
    """True for the file names Docker Compose itself loads by default (and their overrides)."""
    return bool(_COMPOSE_NAME_RE.match(path.name))


def _finding(rule_id: str, severity: str, title: str, message: str, rel_path: str, line: int, compliance: list[str]) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=rel_path,
        line_number=line,
        category="compose",
        compliance=compliance,
    )


def _volume_source(volume: Any) -> str:
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    if isinstance(volume, dict):
        return str(volume.get("source") or "")
    return ""


def _environment_entries(environment: Any) -> list[tuple[str, str, int]]:
    """``(name, literal value, line)`` for each environment entry."""
    entries: list[tuple[str, str, int]] = []
    if isinstance(environment, dict):
        for name, value in environment.items():
            entries.append((str(name), "" if value is None else str(value), key_line(environment, name)))
    elif isinstance(environment, list):
        for index, item in enumerate(environment):
            if isinstance(item, str) and "=" in item:
                name, value = item.split("=", 1)
                entries.append((name.strip(), value.strip(), item_line(environment, index)))
    return entries


def _capability_and_secret_findings(name: str, service: dict[str, Any], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    caps = service.get("cap_add")
    if isinstance(caps, list):
        for index, cap in enumerate(caps):
            if str(cap).strip().upper() in _DANGEROUS_CAPS:
                findings.append(
                    _finding(
                        "COMPOSE-005",
                        "high",
                        f"Compose service adds {str(cap).strip().upper()} capability",
                        f"Service '{name}' adds {str(cap).strip().upper()}, a capability that enables container escape. "
                        "Add only the specific capabilities required.",
                        rel_path,
                        item_line(caps, index, key_line(service, "cap_add")),
                        ["CIS-Docker-5.3", "NIST-AC-6"],
                    )
                )
    environment = service.get("environment")
    for env_name, env_value, line in _environment_entries(environment):
        if is_hardcoded_secret(env_name, env_value):
            findings.append(
                _finding(
                    "COMPOSE-006",
                    "critical",
                    "Hardcoded secret in compose environment",
                    f"Service '{name}' sets environment variable '{env_name}' to a literal value. "
                    "Use Compose secrets or interpolate it from the runtime environment.",
                    rel_path,
                    line or key_line(service, "environment"),
                    ["CIS-Docker-4.10", "NIST-IA-5"],
                )
            )
    return findings


def _scan_service(name: str, service: dict[str, Any], rel_path: str, service_line: int) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    if service.get("privileged") is True:
        findings.append(
            _finding(
                "COMPOSE-001",
                "critical",
                "Compose service runs privileged",
                f"Service '{name}' sets privileged: true, which gives it full access to the host. "
                "Drop privileged and add only the capabilities it needs.",
                rel_path,
                key_line(service, "privileged"),
                ["CIS-Docker-5.4", "NIST-AC-6"],
            )
        )
    volumes = service.get("volumes")
    if isinstance(volumes, list):
        for index, volume in enumerate(volumes):
            if _DOCKER_SOCKET_RE.search(_volume_source(volume)):
                findings.append(
                    _finding(
                        "COMPOSE-002",
                        "critical",
                        "Compose service mounts the Docker socket",
                        f"Service '{name}' mounts /var/run/docker.sock, which grants root-equivalent control of the host's Docker daemon.",
                        rel_path,
                        item_line(volumes, index, key_line(service, "volumes")),
                        ["CIS-Docker-5.31", "NIST-AC-6"],
                    )
                )
    if str(service.get("network_mode", "")).strip() == "host":
        findings.append(
            _finding(
                "COMPOSE-003",
                "high",
                "Compose service uses the host network",
                f"Service '{name}' sets network_mode: host and shares the host network namespace. "
                "Use a bridge network and publish only needed ports.",
                rel_path,
                key_line(service, "network_mode"),
                ["CIS-Docker-5.9", "NIST-SC-7"],
            )
        )
    if str(service.get("pid", "")).strip() == "host":
        findings.append(
            _finding(
                "COMPOSE-004",
                "high",
                "Compose service shares the host PID namespace",
                f"Service '{name}' sets pid: host and can see and signal every host process. Remove pid: host.",
                rel_path,
                key_line(service, "pid"),
                ["CIS-Docker-5.15", "NIST-SC-39"],
            )
        )
    findings.extend(_capability_and_secret_findings(name, service, rel_path))
    findings.extend(hardening_findings(name, service, rel_path, service_line))
    return findings


def scan_compose(file_path: str | Path) -> list[IaCFinding]:
    """Scan one Docker Compose file."""
    path = Path(file_path)
    if not path.is_file():
        return []
    try:
        document = safe_load_with_lines(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return []
    if not isinstance(document, dict):
        return []
    services = document.get("services")
    if not isinstance(services, dict):
        return []
    findings: list[IaCFinding] = []
    for name, service in services.items():
        if isinstance(service, dict):
            findings.extend(_scan_service(str(name), service, str(path), key_line(services, name)))
    return findings
