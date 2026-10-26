"""Distro-aware recognition and grouping of kernel-header package CVEs.

Kernel-header packages (Debian ``linux-libc-dev``, RHEL ``kernel-headers``,
Alpine ``linux-headers``) are versioned with the distro kernel, so they match
the upstream kernel CVE stream: thousands of rows on one package. Console
output folds them into one group line per image distro; machine-readable
formats keep every CVE.

Each rule is scoped to a package ecosystem and to the ``/etc/os-release`` ID
family the image scanner recorded. A package with the same name on another
distro, another ecosystem, or an unknown distro is never grouped.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

_DEBIAN_FAMILY = frozenset({"debian", "ubuntu"})
_REDHAT_FAMILY = frozenset({"rhel", "redhat", "centos", "rocky", "almalinux", "alma", "ol", "fedora", "amzn"})
_SUSE_FAMILY = frozenset({"sles", "sled", "opensuse", "opensuse-leap", "opensuse-tumbleweed"})
_ALPINE_FAMILY = frozenset({"alpine"})


@dataclass(frozen=True)
class KernelHeaderRule:
    ecosystem: str
    distro_ids: frozenset[str]
    names: frozenset[str]
    prefixes: tuple[str, ...] = ()

    def matches(self, name: str, ecosystem: str, distro_id: str) -> bool:
        if ecosystem != self.ecosystem or distro_id not in self.distro_ids:
            return False
        return name in self.names or name.startswith(self.prefixes)


KERNEL_HEADER_RULES: tuple[KernelHeaderRule, ...] = (
    KernelHeaderRule("deb", _DEBIAN_FAMILY, frozenset({"linux-libc-dev"}), ("linux-headers-",)),
    KernelHeaderRule("rpm", _REDHAT_FAMILY, frozenset({"kernel-headers", "kernel-devel"})),
    KernelHeaderRule("rpm", _SUSE_FAMILY, frozenset({"linux-glibc-devel", "kernel-devel", "kernel-default-devel"})),
    KernelHeaderRule("apk", _ALPINE_FAMILY, frozenset({"linux-headers"})),
)

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "none", "unknown")


def is_kernel_header_package(package: Any) -> bool:
    """Whether ``package`` is a kernel-header package on the distro it was found on."""
    distro_id = str(getattr(package, "distro_name", None) or "").strip().lower()
    if not distro_id:
        return False
    name = str(getattr(package, "name", "") or "").lower()
    ecosystem = str(getattr(package, "ecosystem", "") or "").lower()
    return any(rule.matches(name, ecosystem, distro_id) for rule in KERNEL_HEADER_RULES)


def _severity_key(br: Any) -> str:
    severity = getattr(br.vulnerability, "severity", None)
    value = str(getattr(severity, "value", severity) or "unknown").lower()
    return value if value in _SEVERITY_ORDER else "unknown"


@dataclass
class KernelHeaderGroup:
    """Every CVE on the kernel-header packages of one image distro release."""

    ecosystem: str
    distro_name: str
    distro_version: str
    packages: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    kev_ids: list[str] = field(default_factory=list)
    critical_ids: list[str] = field(default_factory=list)
    collapsed: list[Any] = field(default_factory=list)
    total: int = 0

    @property
    def collapsed_count(self) -> int:
        return len(self.collapsed)

    @property
    def distro_label(self) -> str:
        return f"{self.distro_name} {self.distro_version}".strip()

    def add(self, br: Any) -> None:
        package = f"{br.package.name}@{br.package.version}"
        if package not in self.packages:
            self.packages.append(package)
        self.total += 1
        vuln_id = str(br.vulnerability.id)
        if getattr(br.vulnerability, "is_kev", False):
            self.kev_ids.append(vuln_id)
        elif _severity_key(br) == "critical":
            self.critical_ids.append(vuln_id)
        else:
            self.collapsed.append(br)

    def finish(self, severities: Counter[str]) -> None:
        self.packages.sort()
        self.kev_ids.sort()
        self.critical_ids.sort()
        self.severity_counts = {key: severities[key] for key in _SEVERITY_ORDER if severities[key]}


def kernel_header_groups(blast_radii: list[Any]) -> list[KernelHeaderGroup]:
    """Group kernel-header blast radii by ecosystem and distro release.

    KEV and critical CVEs are counted in the group but never collapsed: they
    stay on ``kev_ids``/``critical_ids`` for the caller to render individually.
    """
    groups: dict[tuple[str, str, str], KernelHeaderGroup] = {}
    severities: dict[tuple[str, str, str], Counter[str]] = {}
    for br in blast_radii:
        package = getattr(br, "package", None)
        if package is None or not is_kernel_header_package(package):
            continue
        key = (str(package.ecosystem).lower(), str(package.distro_name).lower(), str(package.distro_version or ""))
        group = groups.setdefault(key, KernelHeaderGroup(*key))
        group.add(br)
        severities.setdefault(key, Counter())[_severity_key(br)] += 1
    for key, group in groups.items():
        group.finish(severities[key])
    return [groups[key] for key in sorted(groups)]
