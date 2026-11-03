"""Advisories matched on a registry-selected version are candidates, not confirmed findings.

When a manifest declares a range (``^4.0.0-beta.3``) and no lockfile or install
records the version, the scanner asks the registry which version a fresh
install would select. Nobody has installed that version, so its advisories are
reported as ``possibly_affected`` review items: never counted in severity
totals, never a ``--fail-on-severity`` trigger, visible in every output.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.models import Agent, AgentType, MCPServer, Package, Severity, Vulnerability
from agent_bom.scanners import package_scan
from agent_bom.scanners.registry_selected_policy import (
    REGISTRY_SELECTED_VERSION,
    demote_registry_selected,
    is_registry_selected,
)
from agent_bom.scanners.scan_options import ScanOptions


def _range_resolved(name: str = "vite", version: str = "4.5.14") -> Package:
    pkg = Package(name=name, version=version, ecosystem="npm", declared_version="^4.0.0-beta.3", resolved_from_registry=True)
    pkg.floating_reference = True
    pkg.version_evidence = [{"type": "registry_range", "declared_version": "^4.0.0-beta.3", "resolved_version": version}]
    return pkg


def _vuln(vid: str, severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(id=vid, summary=f"{vid} summary", severity=severity, fixed_version="4.5.15")


def test_range_resolved_package_is_registry_selected() -> None:
    assert is_registry_selected(_range_resolved())
    locked = Package(name="vite", version="4.0.0", ecosystem="npm", version_source="lockfile")
    assert not is_registry_selected(locked)
    pinned_but_registry_listed = Package(name="srv", version="1.0.0", ecosystem="npm", resolved_from_registry=True)
    assert not is_registry_selected(pinned_but_registry_listed)


def test_demotion_moves_advisories_to_candidates_and_keeps_malicious() -> None:
    pkg = _range_resolved()
    pkg.vulnerabilities = [_vuln("GHSA-aaaa-bbbb-cccc"), _vuln("CVE-2024-0001", Severity.CRITICAL), _vuln("MAL-2024-1")]

    demoted = demote_registry_selected([pkg])

    assert demoted == 2
    assert [v.id for v in pkg.vulnerabilities] == ["MAL-2024-1"]
    entries = {e["id"]: e for e in pkg.possibly_affected}
    assert set(entries) == {"GHSA-aaaa-bbbb-cccc", "CVE-2024-0001"}
    entry = entries["CVE-2024-0001"]
    assert entry["verdict"] == "possibly_affected"
    assert entry["reason"] == REGISTRY_SELECTED_VERSION
    assert entry["match_confidence_tier"] == "unverified_range"
    assert entry["severity"] == "critical"
    assert entry["upstream_fixed_version"] == "4.5.15"
    assert "^4.0.0-beta.3" in entry["detail"] and "4.5.14" in entry["detail"]
    assert demote_registry_selected([pkg]) == 0  # idempotent


def test_override_env_keeps_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_INCLUDE_RANGE_RESOLVED", "1")
    pkg = _range_resolved()
    pkg.vulnerabilities = [_vuln("CVE-2024-0001")]
    assert demote_registry_selected([pkg]) == 0
    assert [v.id for v in pkg.vulnerabilities] == ["CVE-2024-0001"]


def _patch_local_match(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_local(scannable, options, demo_keys):
        for pkg in scannable:
            pkg.vulnerabilities.append(_vuln("CVE-2024-0001"))
        return len(scannable), set(), list(scannable)

    async def no_registry(packages, offline):
        return None

    async def no_osv(*args, **kwargs):
        return {}

    async def no_supplemental(*args, **kwargs):
        return 0

    monkeypatch.setattr(package_scan, "_scan_local_advisories", fake_local)
    monkeypatch.setattr(package_scan, "_resolve_registry_versions", no_registry)
    monkeypatch.setattr(package_scan, "_detect_coverage_gaps", lambda scannable: set())
    monkeypatch.setattr(package_scan, "_query_osv_results", no_osv)
    monkeypatch.setattr(package_scan, "_scan_supplemental_advisories", no_supplemental)


def test_scan_counts_exclude_registry_selected_but_keep_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_local_match(monkeypatch)
    phantom = _range_resolved()
    locked = Package(name="left-pad", version="1.0.0", ecosystem="npm", version_source="lockfile")

    total = asyncio.run(package_scan.scan_packages([phantom, locked], options=ScanOptions()))

    assert total == 1
    assert phantom.vulnerabilities == []
    assert [e["id"] for e in phantom.possibly_affected] == ["CVE-2024-0001"]
    assert [v.id for v in locked.vulnerabilities] == ["CVE-2024-0001"]


def test_check_of_a_named_target_keeps_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_local_match(monkeypatch)
    pkg = _range_resolved()

    total = asyncio.run(package_scan.scan_packages([pkg], options=ScanOptions(registry_selected_as_candidates=False)))

    assert total == 1
    assert [v.id for v in pkg.vulnerabilities] == ["CVE-2024-0001"]


def test_outputs_show_candidates_separately_and_gate_ignores_them() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json
    from agent_bom.output.sarif import to_sarif

    pkg = _range_resolved()
    pkg.vulnerabilities = [_vuln("CVE-2024-0001")]
    demote_registry_selected([pkg])
    server = MCPServer(name="app", command="node", packages=[pkg])
    agent = Agent(name="project", agent_type=AgentType.CUSTOM, config_path="/repo/package.json", mcp_servers=[server])
    report = AIBOMReport(agents=[agent], blast_radii=[])

    data = json.loads(json.dumps(to_json(report), default=str))
    assert data["summary"]["total_vulnerabilities"] == 0
    rows = data["possibly_affected"]
    assert [(r["id"], r["reason"], r["package"]["version"]) for r in rows] == [("CVE-2024-0001", REGISTRY_SELECTED_VERSION, "4.5.14")]

    sarif = to_sarif(report)
    results = sarif["runs"][0]["results"]
    review = [r for r in results if r["ruleId"] == "agent-bom/possibly-affected"]
    assert len(review) == 1 and review[0]["level"] == "note"
    assert review[0]["properties"]["reason"] == REGISTRY_SELECTED_VERSION
    assert not [r for r in results if r["ruleId"] != "agent-bom/possibly-affected" and "CVE-2024-0001" in json.dumps(r)]


def test_resolver_marks_range_resolution_as_registry_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import resolver, transitive

    async def fake_range(name, constraint, client):
        return "4.5.14"

    monkeypatch.setattr(transitive, "resolve_npm_range_version", fake_range)
    pkg = Package(name="vite", version="unknown", ecosystem="npm", declared_version="^4.0.0-beta.3", version_source="manifest")

    assert asyncio.run(resolver._resolve_declared_constraint(pkg, "^4.0.0-beta.3", None))

    assert pkg.version == "4.5.14"
    assert is_registry_selected(pkg)
    assert pkg.version_confidence == "low"
    assert "^4.0.0-beta.3" in (pkg.floating_reference_reason or "")


def test_terminal_heading_names_unconfirmed_version() -> None:
    from rich.console import Console

    from agent_bom.models import AIBOMReport
    from agent_bom.output.possibly_affected import print_possibly_affected

    pkg = _range_resolved()
    pkg.vulnerabilities = [_vuln("CVE-2024-0001")]
    demote_registry_selected([pkg])
    agent = Agent(
        name="project",
        agent_type=AgentType.CUSTOM,
        config_path="/repo/package.json",
        mcp_servers=[MCPServer(name="app", command="node", packages=[pkg])],
    )
    console = Console(record=True, width=200)
    print_possibly_affected(AIBOMReport(agents=[agent], blast_radii=[]), console)
    text = console.export_text()
    assert "Possibly affected — version or advisory unconfirmed (1)" in text
    assert "verify distro advisory" not in text
    assert "vite 4.5.14" in text
