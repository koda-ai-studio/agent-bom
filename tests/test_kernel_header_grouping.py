"""Kernel-header package CVEs collapse into one bounded console group, per distro.

A Debian image's ``linux-libc-dev`` carries the upstream kernel CVE stream
(thousands of rows). Console output groups them; machine formats keep every
CVE. Classification is distro- and ecosystem-scoped: a package that happens to
share a name on another distro or ecosystem is never grouped.
"""

from __future__ import annotations

import re
from io import StringIO

import pytest
from rich.console import Console

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output import print_compact_blast_radius
from agent_bom.output.kernel_headers import is_kernel_header_package, kernel_header_groups


def _pkg(name: str, ecosystem: str, distro: str | None, version: str = "1.0-1", distro_version: str | None = "13") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem, distro_name=distro, distro_version=distro_version, is_direct=False)


@pytest.mark.parametrize(
    ("name", "ecosystem", "distro"),
    [
        ("linux-libc-dev", "deb", "debian"),
        ("linux-libc-dev", "deb", "ubuntu"),
        ("linux-headers-6.8.0-31-generic", "deb", "ubuntu"),
        ("linux-headers-6.1.0-18-amd64", "deb", "debian"),
        ("kernel-headers", "rpm", "rhel"),
        ("kernel-devel", "rpm", "rocky"),
        ("kernel-headers", "rpm", "almalinux"),
        ("kernel-headers", "rpm", "amzn"),
        ("kernel-headers", "rpm", "ol"),
        ("kernel-headers", "rpm", "fedora"),
        ("linux-glibc-devel", "rpm", "opensuse-leap"),
        ("linux-glibc-devel", "rpm", "sles"),
        ("linux-headers", "apk", "alpine"),
    ],
)
def test_kernel_header_packages_are_recognised_on_their_own_distro(name: str, ecosystem: str, distro: str) -> None:
    assert is_kernel_header_package(_pkg(name, ecosystem, distro))


@pytest.mark.parametrize(
    ("name", "ecosystem", "distro"),
    [
        # Same names, wrong distro family or ecosystem.
        ("linux-libc-dev", "rpm", "rhel"),
        ("linux-libc-dev", "apk", "alpine"),
        ("linux-libc-dev", "deb", "alpine"),
        ("kernel-headers", "deb", "debian"),
        ("kernel-headers", "apk", "alpine"),
        ("kernel-headers", "rpm", "debian"),
        ("linux-headers", "deb", "debian"),
        ("linux-headers", "rpm", "rhel"),
        ("linux-headers", "apk", "wolfi"),
        ("linux-glibc-devel", "rpm", "rhel"),
        ("linux-libc-dev", "pypi", None),
        ("kernel-headers", "npm", None),
        # Unknown distro: never guess.
        ("linux-libc-dev", "deb", None),
        ("kernel-headers", "rpm", None),
        ("linux-headers", "apk", None),
        # Not a kernel-header package at all.
        ("linux-base", "deb", "debian"),
        ("libc6-dev", "deb", "debian"),
        ("kernel", "rpm", "rhel"),
    ],
)
def test_same_name_on_another_distro_or_ecosystem_is_not_grouped(name: str, ecosystem: str, distro: str | None) -> None:
    assert not is_kernel_header_package(_pkg(name, ecosystem, distro))


def _br(package: Package, vid: str, severity: Severity = Severity.MEDIUM, *, kev: bool = False) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(id=vid, summary="kernel issue", severity=severity, is_kev=kev),
        package=package,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _kernel_radii() -> tuple[list[BlastRadius], Package, Package]:
    kernel = _pkg("linux-libc-dev", "deb", "debian", version="6.12.74-2")
    openssl = _pkg("libssl3t64", "deb", "debian", version="3.5.5-1")
    radii = [_br(kernel, f"CVE-2025-{30_000 + i}") for i in range(300)]
    radii += [_br(kernel, f"CVE-2025-{40_000 + i}", Severity.HIGH) for i in range(40)]
    radii.append(_br(kernel, "CVE-2024-1086", Severity.HIGH, kev=True))
    radii.append(_br(kernel, "CVE-2025-99999", Severity.CRITICAL))
    radii.append(_br(openssl, "CVE-2026-34182", Severity.CRITICAL))
    radii.append(_br(openssl, "CVE-2026-11111", Severity.LOW))
    return radii, kernel, openssl


def test_groups_partition_by_distro_and_never_collapse_kev_or_critical() -> None:
    radii, _kernel, _openssl = _kernel_radii()
    ubuntu_kernel = _pkg("linux-libc-dev", "deb", "ubuntu", version="6.8.0-31.31", distro_version="24.04")
    radii.append(_br(ubuntu_kernel, "CVE-2025-50000"))

    groups = kernel_header_groups(radii)

    assert [(g.distro_name, g.distro_version) for g in groups] == [("debian", "13"), ("ubuntu", "24.04")]
    debian = groups[0]
    assert debian.total == 342
    assert debian.severity_counts == {"critical": 1, "high": 41, "medium": 300}
    assert debian.kev_ids == ["CVE-2024-1086"]
    assert debian.critical_ids == ["CVE-2025-99999"]
    assert debian.collapsed_count == 340
    collapsed = {id(br) for group in groups for br in group.collapsed}
    kept = [br for br in radii if id(br) not in collapsed]
    assert {br.vulnerability.id for br in kept} == {"CVE-2024-1086", "CVE-2025-99999", "CVE-2026-34182", "CVE-2026-11111"}
    assert sum(len(g.collapsed) for g in groups) + len(kept) == len(radii)


def _capture(fn, *args, **kwargs) -> str:
    import agent_bom.output as out_mod

    buf = StringIO()
    original = out_mod.console
    out_mod.console = Console(file=buf, width=160, force_terminal=True, no_color=True)
    try:
        fn(*args, **kwargs)
    finally:
        out_mod.console = original
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def _report(radii: list[BlastRadius], *packages: Package) -> AIBOMReport:
    server = MCPServer(name="php:8.3.30-cli", command="", packages=list(packages))
    agent = Agent(name="image:php:8.3.30-cli", agent_type=AgentType.CUSTOM, config_path="image", mcp_servers=[server])
    return AIBOMReport(agents=[agent], blast_radii=radii)


def test_compact_console_shows_one_group_line_naming_kev_and_critical() -> None:
    radii, kernel, openssl = _kernel_radii()
    output = _capture(print_compact_blast_radius, _report(radii, kernel, openssl), limit=50)

    lines = output.splitlines()
    starts = [index for index, line in enumerate(lines) if "Kernel-header group" in line]
    assert len(starts) == 1, output
    line = " ".join(lines[starts[0] : starts[0] + 2])
    assert "linux-libc-dev@6.12.74-2" in line
    assert "debian 13" in line
    assert "342 CVEs" in line
    assert "1 KEV (CVE-2024-1086)" in line
    assert "1 critical" in line
    assert "-f json" in line
    # KEV and critical kernel CVEs stay as their own rows; the 340 others do not.
    assert "CVE-2024-1086" in "\n".join(lines[starts[0] + 2 :])
    assert "CVE-2025-99999" in output
    assert "CVE-2025-30000" not in output
    assert "CVE-2025-40000" not in output
    assert "CVE-2026-34182" in output


def test_compact_console_without_kernel_headers_has_no_group_line() -> None:
    openssl = _pkg("libssl3t64", "deb", "debian")
    radii = [_br(openssl, "CVE-2026-34182", Severity.CRITICAL)]
    output = _capture(print_compact_blast_radius, _report(radii, openssl))
    assert "Kernel-header group" not in output
    assert "CVE-2026-34182" in output


def test_wrong_distro_kernel_named_package_is_rendered_individually() -> None:
    impostor = _pkg("kernel-headers", "deb", "debian")
    radii = [_br(impostor, f"CVE-2025-{60_000 + i}", Severity.HIGH) for i in range(3)]
    output = _capture(print_compact_blast_radius, _report(radii, impostor))
    assert "Kernel-header group" not in output
    assert all(f"CVE-2025-{60_000 + i}" in output for i in range(3))


def test_scan_verdict_names_the_kernel_header_share_of_the_totals() -> None:
    from types import SimpleNamespace

    from agent_bom.cli.agents.scan_pipeline.matching import _print_scan_verdict

    radii, _kernel, _openssl = _kernel_radii()
    buf = StringIO()
    st = SimpleNamespace(
        agents=[],
        coverage_warnings=[],
        scan_warnings=[],
        blast_radii=radii,
        con=Console(file=buf, width=200, force_terminal=True, no_color=True),
    )
    _print_scan_verdict(SimpleNamespace(offline=True), st, 0)
    text = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    assert "package CVEs: 2 critical · 41 high · 300 medium · 1 low" in text
    assert "342 of these are kernel-header CVEs (linux-libc-dev@6.12.74-2, debian 13)" in text
