"""Metadata-only config and IOC signals from a mounted side-scan disk.

Reads a bounded set of startup/config paths and records finding type, path,
severity and a stable evidence label; matched file contents never leave.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SideScanDiskFinding:
    """Metadata-only workload disk finding from mounted side-scan content."""

    finding_type: str
    file_path: str
    severity: str
    category: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type,
            "file": self.file_path,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
        }


_DISK_SCAN_MAX_FILES = 500
_DISK_SCAN_MAX_BYTES_PER_FILE = 256 * 1024

_INTERESTING_RELATIVE_PATHS = (
    "etc/crontab",
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/ssh/sshd_config",
    "etc/systemd/system",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "root/.bashrc",
    "root/.profile",
)

_IOC_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"\b(xmrig|kinsing|kdevtmpfsi|masscan)\b", re.IGNORECASE),
        "known_malware_or_scanner_marker",
        "critical",
    ),
    (re.compile(r"(/dev/tcp/|nc\s+-e\b|bash\s+-i\b)", re.IGNORECASE), "reverse_shell_pattern", "high"),
    (
        re.compile(r"\b(curl|wget)\b[^\n|;&]*(\||;|&&)\s*(sh|bash)\b", re.IGNORECASE),
        "download_execute_startup",
        "high",
    ),
)

_CONFIG_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^\s*PermitRootLogin\s+yes\b", re.IGNORECASE | re.MULTILINE), "ssh_root_login_enabled", "medium"),
    (re.compile(r"^\s*PasswordAuthentication\s+yes\b", re.IGNORECASE | re.MULTILINE), "ssh_password_auth_enabled", "medium"),
)


def _iter_interesting_disk_files(mount_point: Path) -> list[Path]:
    files: list[Path] = []
    for relative in _INTERESTING_RELATIVE_PATHS:
        candidate = mount_point / relative
        try:
            if candidate.is_file():
                files.append(candidate)
            elif candidate.is_dir():
                files.extend(path for path in candidate.rglob("*") if path.is_file())
        except OSError:
            continue
        if len(files) >= _DISK_SCAN_MAX_FILES:
            break
    return files[:_DISK_SCAN_MAX_FILES]


def _relative_disk_path(mount_point: Path, path: Path) -> str:
    try:
        return str(path.relative_to(mount_point))
    except ValueError:
        return path.name


def _read_bounded_text(path: Path) -> str:
    try:
        if path.stat().st_size > _DISK_SCAN_MAX_BYTES_PER_FILE:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def scan_workload_disk_findings(mount_point: Path) -> tuple[list[SideScanDiskFinding], list[SideScanDiskFinding]]:
    """Scan mounted workload config/startup files for metadata-only risk signals.

    The output deliberately records finding type, path, severity, and a stable
    evidence label only. It never returns matched file contents.
    """

    config_findings: list[SideScanDiskFinding] = []
    ioc_findings: list[SideScanDiskFinding] = []
    seen: set[tuple[str, str]] = set()
    for path in _iter_interesting_disk_files(mount_point):
        text = _read_bounded_text(path)
        if not text:
            continue
        relative_path = _relative_disk_path(mount_point, path)
        for pattern, finding_type, severity in _IOC_PATTERNS:
            if not pattern.search(text):
                continue
            key = (relative_path, finding_type)
            if key in seen:
                continue
            seen.add(key)
            ioc_findings.append(
                SideScanDiskFinding(
                    finding_type=finding_type,
                    file_path=relative_path,
                    severity=severity,
                    category="ioc",
                    evidence=f"{finding_type}_matched",
                )
            )
        for pattern, finding_type, severity in _CONFIG_PATTERNS:
            if not pattern.search(text):
                continue
            key = (relative_path, finding_type)
            if key in seen:
                continue
            seen.add(key)
            config_findings.append(
                SideScanDiskFinding(
                    finding_type=finding_type,
                    file_path=relative_path,
                    severity=severity,
                    category="configuration",
                    evidence=f"{finding_type}_matched",
                )
            )
    return config_findings, ioc_findings
