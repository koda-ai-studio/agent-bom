"""A runtime no advisory source tracks is a coverage gap, never a clean package."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.coverage import RUNTIME_COVERAGE_UNKNOWN, detect_runtime_coverage_gaps, package_vulnerability_unassessed
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package


def _node() -> Package:
    return Package(
        name="node",
        version="18.20.8",
        ecosystem="generic",
        purl="pkg:generic/nodejs/node@18.20.8",
        cpe="cpe:2.3:a:nodejs:node.js:18.20.8:*:*:*:*:*:*:*",
    )


def _cpe_db(*rows: tuple[str, str]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE cpe_matches (cve_id TEXT, criteria TEXT, vendor TEXT, product TEXT)")
    conn.executemany("INSERT INTO cpe_matches VALUES ('CVE-1', 'c', ?, ?)", rows)
    return conn


def test_runtime_without_any_advisory_source_is_a_coverage_gap() -> None:
    (gap,) = detect_runtime_coverage_gaps([_node()], offline=False, conn=None)
    assert gap["reason"] == RUNTIME_COVERAGE_UNKNOWN
    assert gap["ecosystem"] == "generic"
    assert gap["release"] == "node:18.20.8"
    assert gap["package_count"] == 1
    assert gap["advisory_rows"] == 0


def test_runtime_with_no_local_cpe_ranges_is_a_coverage_gap() -> None:
    gaps = detect_runtime_coverage_gaps([_node()], offline=False, conn=_cpe_db(("python", "python")))
    assert [gap["release"] for gap in gaps] == ["node:18.20.8"]


def test_runtime_with_local_cpe_ranges_was_assessed() -> None:
    assert detect_runtime_coverage_gaps([_node()], offline=False, conn=_cpe_db(("nodejs", "node.js"))) == []


@pytest.mark.parametrize(
    "package",
    [
        Package(name="left-pad", version="1.0.0", ecosystem="npm"),
        Package(name="requests", version="2.31.0", ecosystem="pypi"),
        # CPython has its own upstream advisory lookup that records its own gap.
        Package(name="cpython", version="3.12.1", ecosystem="generic", cpe="cpe:2.3:a:python:python:3.12.1:*:*:*:*:*:*:*"),
    ],
)
def test_packages_with_an_advisory_source_are_not_runtime_gaps(package: Package) -> None:
    assert detect_runtime_coverage_gaps([package], offline=False, conn=None) == []


def test_runtime_that_already_has_findings_was_assessed() -> None:
    from agent_bom.models import Severity, Vulnerability

    node = _node()
    node.vulnerabilities = [Vulnerability(id="CVE-2025-1", summary="x", severity=Severity.HIGH)]
    assert detect_runtime_coverage_gaps([node], offline=False, conn=None) == []


def test_unassessed_judgement_matches_runtime_gap_and_unsupported_rpm() -> None:
    gaps = detect_runtime_coverage_gaps([_node()], offline=False, conn=None)
    assert package_vulnerability_unassessed(_node(), gaps) is True
    assert package_vulnerability_unassessed(Package(name="left-pad", version="1.0.0", ecosystem="npm"), gaps) is False
    rpm = Package(name="bash", version="5.1-1.el9", ecosystem="rpm", distro_name="sles", distro_version="15")
    assert package_vulnerability_unassessed(rpm, []) is True


def _report(*packages: Package, coverage_warnings: list[dict]) -> AIBOMReport:
    server = MCPServer(name="image", command="", packages=list(packages))
    agent = Agent(name="img", agent_type=AgentType.CUSTOM, config_path="/tmp/img", mcp_servers=[server])
    return AIBOMReport(agents=[agent], coverage_warnings=coverage_warnings)


def test_inventory_reports_unassessed_runtime_as_not_scanned() -> None:
    from agent_bom.output.json_inventory import _build_ai_bom_entities_snapshot

    npm = Package(name="left-pad", version="1.0.0", ecosystem="npm")
    gaps = detect_runtime_coverage_gaps([_node()], offline=False, conn=None)
    packages = {p["name"]: p for p in _build_ai_bom_entities_snapshot(_report(_node(), npm, coverage_warnings=gaps))["packages"]}
    assert packages["node"]["vulnerability_status"] == "not_scanned"
    assert packages["node"]["vulnerability_count"] is None
    assert packages["left-pad"]["vulnerability_status"] == "scanned"
    assert packages["left-pad"]["vulnerability_count"] == 0


def test_inventory_reports_unsupported_rpm_as_not_scanned() -> None:
    from agent_bom.output.json_inventory import _build_ai_bom_entities_snapshot

    rpm = Package(name="bash", version="5.1-1.el9", ecosystem="rpm", distro_name="sles", distro_version="15")
    (package,) = _build_ai_bom_entities_snapshot(_report(rpm, coverage_warnings=[]))["packages"]
    assert package["vulnerability_status"] == "not_scanned"
    assert package["vulnerability_count"] is None


@pytest.mark.asyncio
async def test_scan_packages_records_runtime_gap(monkeypatch) -> None:
    from agent_bom.scanners import package_scan
    from agent_bom.scanners.state import capture_coverage_warnings

    async def _no_results(*_args, **_kwargs):
        return {}

    async def _no_supplemental(*_args, **_kwargs):
        return 0

    monkeypatch.setattr("agent_bom.coverage._open_readonly_db", lambda: None)
    monkeypatch.setattr(package_scan, "_scan_local_advisories", lambda *_a: (0, set(), []))
    monkeypatch.setattr(package_scan, "_query_osv_results", _no_results)
    monkeypatch.setattr(package_scan, "_scan_supplemental_advisories", _no_supplemental)
    with capture_coverage_warnings() as warnings:
        await package_scan.scan_packages([_node()], options=package_scan.default_scan_options(offline=False))
    assert any(w.get("reason") == RUNTIME_COVERAGE_UNKNOWN and w.get("release") == "node:18.20.8" for w in warnings)
