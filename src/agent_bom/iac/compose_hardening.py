"""Docker Compose service-hardening rules (COMPOSE-007..011)."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.iac.models import IaCFinding
from agent_bom.iac.yaml_lines import item_line, key_line

_UNCONFINED_RE = re.compile(r"^(?:seccomp|apparmor)[:=]unconfined$|^label[:=]disable$", re.IGNORECASE)
_NO_NEW_PRIVILEGES_RE = re.compile(r"^no-new-privileges(?:[:=](?:true|1))?$", re.IGNORECASE)
_DOCKER_SOCKET_RE = re.compile(r"/docker\.sock$")

# CIS Docker 5.5 system directories: flagged when the directory itself is mounted.
_SENSITIVE_DIRS = frozenset({"/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr", "/root", "/run", "/var/run", "/home"})
# Flagged when mounted or anything beneath them is.
_SENSITIVE_PREFIXES = ("/var/lib/docker", "/var/lib/kubelet", "/etc/kubernetes", "/root/", "/etc/shadow", "/etc/sudoers", "/etc/ssh")
_SENSITIVE_SEGMENTS = frozenset({".ssh", ".aws", ".kube", ".gnupg", ".docker"})

_HOST_NAMESPACES: tuple[tuple[str, str, str, str], ...] = (
    ("ipc", "high", "host IPC namespace", "can read host shared memory and semaphores"),
    ("uts", "medium", "host UTS namespace", "can change the host's hostname"),
    ("userns_mode", "high", "host user namespace", "turns off user-namespace remapping, so container root is host root"),
)


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


def _security_opts(service: dict[str, Any]) -> list[str]:
    opts = service.get("security_opt")
    return [str(opt).strip() for opt in opts] if isinstance(opts, list) else []


def _security_opt_findings(name: str, service: dict[str, Any], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    opts = service.get("security_opt")
    for index, opt in enumerate(_security_opts(service)):
        if _UNCONFINED_RE.match(opt):
            findings.append(
                _finding(
                    "COMPOSE-007",
                    "high",
                    "Compose service disables seccomp, AppArmor or SELinux confinement",
                    f"Service '{name}' sets security_opt '{opt}', removing a kernel confinement layer that blocks container escapes. "
                    "Use the default profile or a custom one.",
                    rel_path,
                    item_line(opts, index, key_line(service, "security_opt")),
                    ["CIS-Docker-5.1", "CIS-Docker-5.2", "CIS-Docker-5.21", "NIST-AC-6"],
                )
            )
    if service.get("privileged") is not True and not any(_NO_NEW_PRIVILEGES_RE.match(opt) for opt in _security_opts(service)):
        findings.append(
            _finding(
                "COMPOSE-011",
                "low",
                "Compose service does not set no-new-privileges",
                f"Service '{name}' lets processes gain privileges through setuid binaries. Add 'no-new-privileges:true' to security_opt.",
                rel_path,
                0,
                ["CIS-Docker-5.25", "NIST-AC-6"],
            )
        )
    return findings


def _namespace_findings(name: str, service: dict[str, Any], rel_path: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for key, severity, label, impact in _HOST_NAMESPACES:
        if str(service.get(key, "")).strip() == "host":
            findings.append(
                _finding(
                    "COMPOSE-008",
                    severity,
                    f"Compose service shares the {label}",
                    f"Service '{name}' sets {key}: host and {impact}. Remove {key}: host.",
                    rel_path,
                    key_line(service, key),
                    ["CIS-Docker-5.16" if key == "ipc" else "CIS-Docker-5.20" if key == "uts" else "CIS-Docker-5.30", "NIST-SC-39"],
                )
            )
    return findings


def _bind_source(volume: Any) -> str:
    if isinstance(volume, str):
        source = volume.split(":", 1)[0] if ":" in volume else ""
    elif isinstance(volume, dict) and str(volume.get("type", "bind")) == "bind":
        source = str(volume.get("source") or "")
    else:
        return ""
    return source.strip()


def is_sensitive_host_path(source: str) -> bool:
    """A bind-mount source that exposes host system directories or credentials."""
    if not source.startswith(("/", "~")) or _DOCKER_SOCKET_RE.search(source):
        return False
    path = "/" + source.strip("/") if source.startswith("/") else source
    if path in _SENSITIVE_DIRS or any(path == p.rstrip("/") or path.startswith(p) for p in _SENSITIVE_PREFIXES):
        return True
    return any(part in _SENSITIVE_SEGMENTS for part in path.split("/"))


def _mount_findings(name: str, service: dict[str, Any], rel_path: str) -> list[IaCFinding]:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        return []
    findings: list[IaCFinding] = []
    for index, volume in enumerate(volumes):
        source = _bind_source(volume)
        if source and is_sensitive_host_path(source):
            findings.append(
                _finding(
                    "COMPOSE-009",
                    "high",
                    "Compose service mounts a sensitive host path",
                    f"Service '{name}' bind-mounts host path '{source}', exposing host system files or credentials to the container. "
                    "Mount only the application directories it needs.",
                    rel_path,
                    item_line(volumes, index, key_line(service, "volumes")),
                    ["CIS-Docker-5.5", "NIST-AC-6", "NIST-SC-39"],
                )
            )
    return findings


def _user_findings(name: str, service: dict[str, Any], rel_path: str) -> list[IaCFinding]:
    user = str(service.get("user", "")).strip().strip("'\"")
    if user.split(":", 1)[0] not in ("root", "0"):
        return []
    return [
        _finding(
            "COMPOSE-010",
            "high",
            "Compose service runs as root",
            f"Service '{name}' sets user: {user}. Run it as a non-root UID:GID such as \"10001:10001\".",
            rel_path,
            key_line(service, "user"),
            ["CIS-Docker-4.1", "NIST-AC-6"],
        )
    ]


def hardening_findings(name: str, service: dict[str, Any], rel_path: str, service_line: int) -> list[IaCFinding]:
    """COMPOSE-007..011 for one service; findings without a key of their own point at ``service_line``."""
    findings = (
        _security_opt_findings(name, service, rel_path)
        + _namespace_findings(name, service, rel_path)
        + _mount_findings(name, service, rel_path)
        + _user_findings(name, service, rel_path)
    )
    for finding in findings:
        if not finding.line_number:
            finding.line_number = service_line
    return findings
