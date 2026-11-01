"""Advisory scores must survive sync without inventing severity or losing zero."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from agent_bom.core.cvss import normalize_cvss_score
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _copy_local_nvd_score, sync_nvd
from agent_bom.db.sync_common import _normalize_sync_cvss_score
from agent_bom.db.sync_nvd_window import _upsert_nvd_cve
from agent_bom.db.sync_parsing import _extract_nvd_cve_fields
from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import Package
from agent_bom.scanners.local_advisories import _scan_packages_db_conn


def _metric(score, *, kind="Primary", vector="CVSS:3.1/fixture"):
    return {"type": kind, "cvssData": {"baseScore": score, "baseSeverity": "HIGH", "vectorString": vector}}


@pytest.mark.parametrize("score", [True, False, float("nan"), float("inf"), -1, 11, 10**400, "not-a-score"])
def test_invalid_score_cannot_become_an_assessed_severity(score):
    fields = _extract_nvd_cve_fields({"metrics": {"cvssMetricV31": [_metric(score)]}})
    assert fields["cvss_score"] is None
    assert fields["severity"] is None
    assert fields["cvss_vector"] is None
    json.dumps(fields, allow_nan=False)


@pytest.mark.parametrize("score", [True, False, 10**400, -(10**400)])
def test_online_and_database_normalizers_reject_the_same_invalid_numbers(score):
    assert normalize_cvss_score(score) is None
    assert _normalize_sync_cvss_score(score) is None


def test_valid_primary_assessment_wins_over_secondary_and_invalid_entries():
    metrics = {
        "cvssMetricV40": [_metric(9.2, kind="Secondary", vector="CVSS:4.0/secondary")],
        "cvssMetricV31": [None, _metric(11), _metric(6.5, vector="CVSS:3.1/primary")],
    }
    fields = _extract_nvd_cve_fields({"metrics": metrics})
    assert (fields["cvss_score"], fields["severity"], fields["cvss_vector"]) == (6.5, "medium", "CVSS:3.1/primary")


def test_newest_valid_primary_metric_is_used_with_older_version_fallback():
    metrics = {"cvssMetricV40": [_metric(9.2, vector="CVSS:4.0/primary")], "cvssMetricV31": [_metric(6.5)]}
    assert _extract_nvd_cve_fields({"metrics": metrics})["cvss_score"] == 9.2
    metrics["cvssMetricV40"][0]["cvssData"]["baseScore"] = float("inf")
    assert _extract_nvd_cve_fields({"metrics": metrics})["cvss_score"] == 6.5


@pytest.mark.parametrize("metrics", [None, [], "invalid", {"cvssMetricV31": [None, {"cvssData": []}]}])
def test_malformed_metrics_do_not_discard_independent_cwe_evidence(metrics):
    fields = _extract_nvd_cve_fields({"metrics": metrics, "weaknesses": [{"description": [{"value": "CWE-79"}]}]})
    assert fields["cvss_score"] is None
    assert fields["cwe_ids"] == ["CWE-79"]


def test_nvd_base_score_does_not_accept_a_vector_in_place_of_a_number():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    fields = _extract_nvd_cve_fields({"metrics": {"cvssMetricV31": [_metric(vector)]}})
    assert fields["cvss_score"] is None
    assert fields["severity"] is None


@pytest.mark.parametrize(("score", "severity"), [(0.0, "none"), (9.2, "critical")])
def test_incremental_ingest_persists_valid_v4_scores_including_zero(score, severity):
    conn = init_db(Path(":memory:"))
    try:
        cve = {"id": "CVE-2026-90001", "metrics": {"cvssMetricV40": [_metric(score, vector="CVSS:4.0/fixture")]}}
        assert _upsert_nvd_cve(conn, cve)
        row = conn.execute("SELECT cvss_score, severity, cvss_vector FROM vulns WHERE id = ?", (cve["id"],)).fetchone()
        assert tuple(row) == (score, severity, "CVSS:4.0/fixture")
    finally:
        conn.close()


@pytest.mark.parametrize(("score", "expected"), [(float("inf"), None), (True, None), (0.0, 0.0), (9.2, 9.2)])
def test_backfill_uses_the_same_validated_metric_selection(monkeypatch, score, expected):
    conn = init_db(Path(":memory:"))
    cve_id = "CVE-2026-90002"
    try:
        conn.execute("INSERT INTO vulns (id, summary, severity, source) VALUES (?, 'fixture', 'unknown', 'osv')", (cve_id,))
        payload = {"vulnerabilities": [{"cve": {"id": cve_id, "metrics": {"cvssMetricV40": [_metric(score)]}}}]}
        monkeypatch.setattr("agent_bom.http_client.fetch_json", lambda *a, **kw: payload)
        count = sync_nvd(conn, max_entries=1)
        row = conn.execute("SELECT cvss_score, severity FROM vulns WHERE id = ?", (cve_id,)).fetchone()
        assert row["cvss_score"] == expected
        assert count == (expected is not None)
        if expected is None:
            assert row["severity"] == "unknown"
    finally:
        conn.close()


@pytest.mark.parametrize("score", [float("inf"), -1, 11])
def test_invalid_legacy_cache_scores_are_not_copied_into_aliases(score):
    conn = init_db(Path(":memory:"))
    try:
        conn.execute(
            "INSERT INTO vulns (id, summary, source, cvss_score, severity) VALUES ('CVE-2026-90003', 'fixture', 'nvd', ?, 'critical')",
            (score,),
        )
        conn.execute("INSERT INTO vulns (id, summary, source, severity) VALUES ('GHSA-fixture', 'fixture', 'osv', 'unknown')")
        assert not _copy_local_nvd_score(conn, "GHSA-fixture", "CVE-2026-90003")
        assert conn.execute("SELECT cvss_score FROM vulns WHERE id = 'GHSA-fixture'").fetchone()[0] is None
    finally:
        conn.close()


@pytest.mark.parametrize(("score", "severity", "expected"), [(9.2, "critical", 9.2), (0.0, "none", 0.0), (float("inf"), "unknown", None)])
def test_nvd_score_reaches_offline_package_matching_and_graph_without_false_certainty(score, severity, expected):
    conn = init_db(Path(":memory:"))
    cve_id = "CVE-2026-90004"
    cpe = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
    package = Package(name="widget", version="1.0", ecosystem="generic", cpe=cpe)
    cve = {
        "id": cve_id,
        "metrics": {"cvssMetricV40": [_metric(score)]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}],
    }
    try:
        assert _upsert_nvd_cve(conn, cve)
        _scan_packages_db_conn(conn, [package], set())
    finally:
        conn.close()
    assert len(package.vulnerabilities) == 1
    vulnerability = package.vulnerabilities[0]
    assert (vulnerability.id, vulnerability.severity.value, vulnerability.cvss_score) == (cve_id, severity, expected)
    report = {
        "agents": [
            {
                "name": "fixture-agent",
                "type": "custom",
                "mcp_servers": [{"name": "fixture-server", "packages": [asdict(package)]}],
            }
        ]
    }
    graph = build_unified_graph_from_report(report)
    findings = graph.nodes_by_type(EntityType.VULNERABILITY)
    assert len(findings) == 1
    assert findings[0].severity == severity
    assert findings[0].attributes["cvss_score"] == expected
    assessment = findings[0].attributes["exploitability_assessment"]
    assert "local_exploitability_not_collected" in assessment["reason_codes"]
    packages = graph.nodes_by_type(EntityType.PACKAGE)
    assert len(packages) == 1
    assert any(
        edge.source == packages[0].id and edge.target == findings[0].id and edge.relationship is RelationshipType.VULNERABLE_TO
        for edge in graph.edges
    )
    assert not any(edge.relationship is RelationshipType.EXPLOITABLE_VIA for edge in graph.edges)
    json.dumps(graph.to_dict(), allow_nan=False)
