"""Reference-image CVE sets are identical before and after kernel-header grouping.

The php:8.3.30-cli set is frozen from main before grouping existed; the
alpine 3.14.2 set is the distro-confirmed reference in
``test_image_scan_parity.py``. Every machine format must still carry every
(CVE, package) pair, and the console must account for every CVE as either a
row or a counted member of a kernel-header group.
"""

from __future__ import annotations

import json
import re
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from agent_bom.kernel_headers import kernel_header_groups
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output import print_compact_blast_radius, to_cyclonedx, to_json, to_sarif
from agent_bom.output.finding_views import active_cve_findings
from agent_bom.output.kernel_header_console import collapse_kernel_header_findings
from tests.test_image_scan_parity import TRIVY_ALPINE_3_14_2_CVES

FIXTURE = Path(__file__).parent / "fixtures" / "image_reference_php_8_3_30_cli_cves.json"
Triple = tuple[str, str, str]


def _php_reference() -> tuple[str, list[tuple[Package, str, Severity, bool]]]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    distro, distro_version = data["distro"]
    kev = set(data["kev"])
    rows = []
    for coordinate, by_severity in data["packages"].items():
        name, version = coordinate.rsplit("@", 1)
        package = Package(
            name=name, version=version, ecosystem=data["ecosystem"], distro_name=distro, distro_version=distro_version, is_direct=False
        )
        for severity, ids in by_severity.items():
            rows += [(package, cve, Severity(severity), f"{cve}|{coordinate}" in kev) for cve in ids]
    return data["image"], rows


def _alpine_reference() -> tuple[str, list[tuple[Package, str, Severity, bool]]]:
    package = Package(name="busybox", version="1.33.1-r3", ecosystem="apk", distro_name="alpine", distro_version="3.14.2", is_direct=False)
    return "alpine:3.14.2", [(package, cve, Severity.HIGH, False) for cve in sorted(TRIVY_ALPINE_3_14_2_CVES)]


def _report(image: str, rows: list[tuple[Package, str, Severity, bool]]) -> tuple[AIBOMReport, set[Triple]]:
    packages = list({id(pkg): pkg for pkg, *_ in rows}.values())
    radii = []
    for package, cve, severity, is_kev in rows:
        vuln = Vulnerability(id=cve, summary=f"{cve} reference", severity=severity, is_kev=is_kev)
        package.vulnerabilities.append(vuln)
        radii.append(
            BlastRadius(
                vulnerability=vuln, package=package, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[]
            )
        )
    server = MCPServer(name=image, command="", packages=packages)
    agent = Agent(name=f"image:{image}", agent_type=AgentType.CUSTOM, config_path="image", mcp_servers=[server])
    for br in radii:
        br.affected_servers, br.affected_agents = [server], [agent]
    expected = {(cve, pkg.name, pkg.version) for pkg, cve, *_ in rows}
    return AIBOMReport(agents=[agent], blast_radii=radii), expected


_SCALE_LANE = [pytest.mark.slow, pytest.mark.scan_performance]


def _build(name: str) -> tuple[str, AIBOMReport, set[Triple]]:
    image, rows = _php_reference() if name == "php" else _alpine_reference()
    report, expected = _report(image, rows)
    return name, report, expected


@pytest.fixture(scope="module", params=[pytest.param("php", marks=_SCALE_LANE), "alpine"])
def reference(request: pytest.FixtureRequest) -> tuple[str, AIBOMReport, set[Triple]]:
    """Machine-format exports; the 4,424-CVE php export runs in the measured scale lane."""
    return _build(request.param)


@pytest.fixture(scope="module", params=["php", "alpine"])
def console_reference(request: pytest.FixtureRequest) -> tuple[str, AIBOMReport, set[Triple]]:
    return _build(request.param)


def test_reference_fixture_matches_the_frozen_totals() -> None:
    _image, rows = _php_reference()
    assert len(rows) == 4424
    assert sum(1 for pkg, *_ in rows if pkg.name == "linux-libc-dev") == 3513


def test_json_carries_every_reference_cve(reference: tuple[str, AIBOMReport, set[Triple]]) -> None:
    _name, report, expected = reference
    doc = to_json(report)
    findings = {
        (f["cve_id"], f["evidence"]["package_name"], f["evidence"]["package_version"])
        for f in doc["findings"]
        if f["finding_type"] == "CVE"
    }
    blast = {(row["vulnerability_id"], row["package"].rsplit("@", 1)[0], row["package"].rsplit("@", 1)[1]) for row in doc["blast_radius"]}
    assert findings == expected
    assert blast == expected


def test_sarif_and_cyclonedx_carry_every_reference_cve(reference: tuple[str, AIBOMReport, set[Triple]]) -> None:
    _name, report, expected = reference
    sarif_ids = {result["ruleId"] for run in to_sarif(report)["runs"] for result in run["results"]}
    cdx_ids = {vuln["id"] for vuln in to_cyclonedx(report)["vulnerabilities"]}
    assert {cve for cve, *_ in expected} <= sarif_ids
    assert cdx_ids == {cve for cve, *_ in expected}


def test_console_accounts_for_every_reference_cve(console_reference: tuple[str, AIBOMReport, set[Triple]]) -> None:
    name, report, expected = console_reference
    findings = active_cve_findings(report)
    kept, groups = collapse_kernel_header_findings(report, findings)
    collapsed = {(str(br.vulnerability.id), br.package.name, br.package.version) for g in groups for br in g.collapsed}
    rows = {(str(f.cve_id), f.evidence["package_name"], f.evidence["package_version"]) for f in kept}

    assert rows | collapsed == expected
    assert not rows & collapsed
    assert sum(g.total for g in groups) == sum(1 for br in report.blast_radii if br.package.name == "linux-libc-dev")
    for group in groups:
        assert not [br for br in group.collapsed if br.vulnerability.is_kev or br.vulnerability.severity is Severity.CRITICAL]
    if name == "alpine":
        assert groups == [] and rows == expected


def test_php_console_title_and_group_line_reconcile_with_the_total() -> None:
    image, rows = _php_reference()
    report, expected = _report(image, rows)
    import agent_bom.output as out_mod

    buf = StringIO()
    original = out_mod.console
    out_mod.console = Console(file=buf, width=200, force_terminal=True, no_color=True)
    try:
        print_compact_blast_radius(report)
    finally:
        out_mod.console = original
    text = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    (group,) = kernel_header_groups(report.blast_radii)
    shown = re.search(r"of (\d+) · (\d+) more below priority", text)
    assert shown, text
    assert int(shown.group(1)) + int(shown.group(2)) + group.collapsed_count == len(expected)
    assert f"{group.collapsed_count} collapsed" in text
    assert "3 KEV (CVE-2026-31431, CVE-2026-53266, CVE-2026-53362)" in text
