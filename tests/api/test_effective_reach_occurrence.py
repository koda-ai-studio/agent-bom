"""Effective reach is per occurrence: a shared CVE id never lends agent context."""

from __future__ import annotations

import pytest

from agent_bom.api import scan_finding_projection as scan
from tests.api.test_api_scan_findings_wiring import KNOWN_CVE, _report_with_known_vuln
from tests.test_scan_snapshot import _job


def _k8s_occurrence() -> dict:
    return {
        "schema_version": "1",
        "id": "k8s-occurrence-of-shared-cve",
        "canonical_id": "k8s-occurrence-of-shared-cve",
        "finding_type": "CVE",
        "finding_category": "vulnerability",
        "source": "CONTAINER",
        "severity": "critical",
        "title": f"{KNOWN_CVE}: demo-lib@1.0.0 in a cluster image",
        "cve_id": KNOWN_CVE,
        "vulnerability_id": KNOWN_CVE,
        "cvss_score": 9.8,
        "epss_score": 0.42,
        "affected_agents": [],
        "affected_servers": [],
        "asset": {"name": "payments-api", "asset_type": "container_image", "identifier": "k8s://prod/payments-api"},
        "evidence": {"package_name": "demo-lib", "package_version": "1.0.0", "ecosystem": "pypi"},
    }


@pytest.fixture
def findings(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    report = _report_with_known_vuln()
    report["findings"].append(_k8s_occurrence())
    return scan._iter_scan_findings(_job(result=report))


def _rows_for(findings: list[dict], vuln_id: str) -> list[dict]:
    return [row for row in findings if (row.get("vulnerability_id") or row.get("cve_id")) == vuln_id]


def test_unlinked_occurrence_of_shared_cve_gets_no_agent_tool_or_credential_context(findings):
    k8s = [row for row in findings if row.get("id") == "k8s-occurrence-of-shared-cve"]
    assert len(k8s) == 1
    reach = k8s[0]["effective_reach"]
    assert reach["agent_breadth"] == 0
    assert reach["tool_capability"] == 0.0
    assert reach["cred_visibility"] == 0.0
    assert reach["reachable_agents"] == [] and reach["reachable_tools"] == [] and reach["reachable_creds"] == []
    # Its own CVSS/EPSS still rank it.
    assert reach["cvss"] == 9.8
    assert reach["epss"] == 0.42
    assert k8s[0]["effective_reach_score"] == reach["composite"]


def test_agent_linked_occurrence_keeps_its_own_context_and_epss(findings):
    linked = [row for row in _rows_for(findings, KNOWN_CVE) if row.get("affected_agents")]
    assert linked
    for row in linked:
        reach = row["effective_reach"]
        assert reach["agent_breadth"] == 1
        assert reach["reachable_agents"] == ["demo-agent"]
        assert reach["tool_capability"] == 1.0
        assert reach["epss"] == 0.9
        assert reach["is_kev"] is True


def test_reach_is_scored_after_representations_merge(monkeypatch):
    """EPSS backfilled from the blast representation must reach the score."""
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    report = _report_with_known_vuln()
    unified = next(row for row in report["findings"] if row.get("cve_id") == KNOWN_CVE or row.get("vulnerability_id") == KNOWN_CVE)
    unified.pop("epss_score", None)
    (unified.get("evidence") or {}).pop("epss_score", None)
    rows = [row for row in scan._iter_scan_findings(_job(result=report)) if row.get("affected_agents")]
    assert rows and all(row["epss_score"] == 0.9 for row in rows)
    assert all(row["effective_reach"]["epss"] == 0.9 for row in rows)


def test_shared_occurrence_id_resolves_context_only_for_the_rows_own_agents():
    """Occurrence ids can repeat across blast rows; context follows the row's own agents."""
    from agent_bom.effective_reach import occurrence_context_for_row

    report = _report_with_known_vuln()
    linked = report["blast_radius"][0]
    reach = scan._effective_reach_lookup(_job(result=report))

    assert occurrence_context_for_row(reach, {"canonical_id": linked["canonical_id"], "affected_agents": []}) is None
    assert occurrence_context_for_row(reach, {"canonical_id": linked["canonical_id"], "affected_agents": ["other-agent"]}) is None
    own = occurrence_context_for_row(reach, {"canonical_id": linked["canonical_id"], "affected_agents": ["demo-agent"]})
    assert own is not None and own["reachable_agents"] == ["demo-agent"]


def test_no_cve_row_carries_agent_context_without_affected_agents(findings):
    borrowed = [
        row
        for row in findings
        if isinstance(row.get("effective_reach"), dict) and row["effective_reach"].get("agent_breadth") and not row.get("affected_agents")
    ]
    assert borrowed == []
