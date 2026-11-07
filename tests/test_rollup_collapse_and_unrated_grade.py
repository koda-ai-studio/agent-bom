"""Collapsing a covered rollup keeps its evidence, and unrated results earn no grade."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace

from agent_bom.core.severity import severity_basis, severity_linked_cve
from agent_bom.evidence.scan_run import ScanRun, scanner_warning_issues, vulnerability_coverage_incomplete
from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.cyclonedx_fmt import _cyclonedx_vulnerability
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif
from agent_bom.posture import compute_posture_scorecard
from agent_bom.scanners.advisory_merge import merge_advisory_clusters

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _rollup(*cves: str, severity: Severity = Severity.CRITICAL, **overrides: object) -> Vulnerability:
    fields: dict = {
        "id": "DSA-5514-1",
        "summary": "rollup",
        "severity": severity,
        "fixed_version": "2.31-13+deb11u7",
        "upstream_ids": list(cves),
        "references": ["https://example.test/dsa"],
        "advisory_sources": ["osv"],
    }
    if severity == Severity.CRITICAL:
        fields.update(cvss_score=9.8, cvss_vector=VECTOR)
    fields.update(overrides)
    return Vulnerability(**fields)


def _cve(cve_id: str, severity: Severity = Severity.UNKNOWN, **overrides: object) -> Vulnerability:
    return Vulnerability(id=cve_id, summary="", severity=severity, fixed_version="2.31-13+deb11u7", advisory_sources=["osv"], **overrides)


def test_collapse_keeps_the_rollup_critical_cvss_and_kev() -> None:
    rollup = _rollup(
        "CVE-2023-4911",
        is_kev=True,
        kev_cve_id="CVE-2023-4911",
        kev_date_added="2023-11-21",
        kev_due_date="2023-12-12",
    )

    merged = merge_advisory_clusters([rollup, _cve("CVE-2023-4911")])

    assert [record.id for record in merged] == ["CVE-2023-4911"]
    record = merged[0]
    assert record.severity == Severity.CRITICAL
    assert record.cvss_score == 9.8
    assert record.cvss_vector == VECTOR
    assert record.severity_source == "advisory:DSA-5514-1"
    assert record.is_kev is True
    assert record.kev_cve_id == "CVE-2023-4911"
    assert record.kev_date_added == "2023-11-21"
    assert record.kev_due_date == "2023-12-12"
    assert "https://example.test/dsa" in record.references


def test_collapse_never_downgrades_a_stronger_cve_record() -> None:
    merged = merge_advisory_clusters(
        [
            _rollup("CVE-2023-4911", severity=Severity.MEDIUM, cvss_score=5.0),
            _cve("CVE-2023-4911", Severity.HIGH, cvss_score=7.8, severity_source="cvss"),
        ]
    )

    assert merged[0].severity == Severity.HIGH
    assert merged[0].cvss_score == 7.8
    assert merged[0].severity_source == "cvss"


def test_collapse_applies_a_linked_score_to_the_cve_it_came_from() -> None:
    rollup = _rollup("CVE-2023-0001", "CVE-2023-0002", severity_source="upstream_cve:CVE-2023-0002")

    merged = merge_advisory_clusters([rollup, _cve("CVE-2023-0001", Severity.LOW), _cve("CVE-2023-0002")])

    by_id = {record.id: record for record in merged}
    assert by_id["CVE-2023-0001"].severity == Severity.LOW
    assert by_id["CVE-2023-0002"].severity == Severity.CRITICAL
    assert by_id["CVE-2023-0002"].severity_source == "upstream_cve:CVE-2023-0002"


def test_collapse_keeps_one_critical_when_the_rollup_names_no_source_cve() -> None:
    """The rollup was one critical finding; it stays one, on the strongest target, deterministically."""
    merged = merge_advisory_clusters(
        [_rollup("CVE-2023-0001", "CVE-2023-0002"), _cve("CVE-2023-0001", Severity.LOW), _cve("CVE-2023-0002", Severity.MEDIUM)]
    )

    by_id = {record.id: record for record in merged}
    assert by_id["CVE-2023-0001"].severity == Severity.LOW
    assert by_id["CVE-2023-0002"].severity == Severity.CRITICAL
    assert sum(record.severity == Severity.CRITICAL for record in merged) == 1


def test_collapse_places_kev_on_the_cve_the_catalog_named() -> None:
    rollup = _rollup("CVE-2023-0001", "CVE-2023-0002", severity=Severity.UNKNOWN, is_kev=True, kev_cve_id="CVE-2023-0001")

    merged = merge_advisory_clusters([rollup, _cve("CVE-2023-0001"), _cve("CVE-2023-0002", Severity.HIGH)])

    by_id = {record.id: record for record in merged}
    assert by_id["CVE-2023-0001"].is_kev is True
    assert by_id["CVE-2023-0002"].is_kev is False


def test_collapse_of_an_unrated_rollup_invents_nothing() -> None:
    merged = merge_advisory_clusters([_rollup("CVE-2023-4911", severity=Severity.UNKNOWN), _cve("CVE-2023-4911")])

    assert merged[0].severity == Severity.UNKNOWN
    assert merged[0].cvss_score is None
    assert merged[0].is_kev is False
    assert merged[0].severity_source is None


def test_collapse_does_not_let_a_namespace_default_outrank_a_rating() -> None:
    merged = merge_advisory_clusters(
        [
            _rollup("CVE-2023-4911", severity=Severity.HIGH, severity_source="ghsa_heuristic"),
            _cve("CVE-2023-4911", Severity.LOW, severity_source="cvss", cvss_score=3.0),
        ]
    )

    assert merged[0].severity == Severity.LOW


def _report(*vulns: Vulnerability) -> AIBOMReport:
    pkg = Package(name="libc-bin", version="2.31-13+deb11u3", ecosystem="deb", vulnerabilities=list(vulns))
    report = AIBOMReport(
        agents=[],
        blast_radii=[
            BlastRadius(vulnerability=vuln, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[])
            for vuln in vulns
        ],
        generated_at=datetime(2026, 11, 7, tzinfo=timezone.utc),
    )
    return report


def _unknown(vid: str = "DSA-1-1") -> Vulnerability:
    return Vulnerability(id=vid, summary="", severity=Severity.UNKNOWN, fixed_version="2")


def test_all_unknown_findings_earn_no_grade() -> None:
    scorecard = compute_posture_scorecard(_report(_unknown("DSA-1-1"), _unknown("DSA-2-1")))

    assert scorecard.grade == "N/A"
    assert scorecard.no_data is True
    assert "severity" in scorecard.summary.lower()


def test_mixed_findings_grade_and_state_how_many_are_unrated() -> None:
    rated = Vulnerability(id="DSA-3-1", summary="", severity=Severity.HIGH, cvss_score=7.5, severity_source="upstream_cve:CVE-2024-1")

    scorecard = compute_posture_scorecard(_report(_unknown(), rated))

    assert scorecard.grade != "N/A"
    assert "1 of 2" in scorecard.summary


def test_rated_findings_carry_no_unrated_caveat() -> None:
    rated = Vulnerability(id="DSA-3-1", summary="", severity=Severity.HIGH, cvss_score=7.5, severity_source="cvss")

    assert "no severity" not in compute_posture_scorecard(_report(rated)).summary


def test_severity_gap_warning_blocks_the_grade() -> None:
    """A failed lookup is recorded as a warning; the coverage gate must read it as incomplete."""
    rated = Vulnerability(id="DSA-3-1", summary="", severity=Severity.HIGH, cvss_score=7.5, severity_source="cvss")
    report = _report(_unknown(), rated)
    report.scan_run = ScanRun(issues=scanner_warning_issues(["Severity is missing for 1 distro advisories: linked CVE lookups failed."]))

    assert vulnerability_coverage_incomplete(report) is True
    assert compute_posture_scorecard(report).grade == "N/A"


def test_linked_basis_and_cve_are_derived_from_the_source() -> None:
    assert severity_basis("upstream_cve:CVE-2024-1") == "linked_cve"
    assert severity_linked_cve("upstream_cve:CVE-2024-1") == "CVE-2024-1"
    assert severity_linked_cve("advisory:DSA-1-1") is None
    assert severity_linked_cve(None) is None


def _linked() -> Vulnerability:
    return Vulnerability(
        id="DSA-5514-1",
        summary="",
        severity=Severity.HIGH,
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity_source="upstream_cve:CVE-2023-4911",
        severity_note="Strongest of 1 of 2 linked CVEs; 1 could not be looked up.",
        upstream_ids=["CVE-2023-4911"],
    )


def test_json_report_states_the_linked_cve() -> None:
    row = to_json(_report(_linked()))["blast_radius"][0]

    assert row["severity"] == "high"
    assert row["severity_source"] == "upstream_cve:CVE-2023-4911"
    assert row["severity_basis"] == "linked_cve"
    assert row["severity_linked_cve"] == "CVE-2023-4911"
    assert row["severity_note"].startswith("Strongest of")


def test_finding_evidence_states_the_linked_cve() -> None:
    report = _report(_linked())

    evidence = blast_radius_to_finding(report.blast_radii[0]).evidence

    assert evidence["severity_source"] == "upstream_cve:CVE-2023-4911"
    assert evidence["severity_basis"] == "linked_cve"
    assert evidence["severity_linked_cve"] == "CVE-2023-4911"
    assert evidence["severity_note"].startswith("Strongest of")


def test_sarif_states_the_linked_cve() -> None:
    document = to_sarif(_report(_linked()))

    results = [result for run in document["runs"] for result in run["results"] if result["ruleId"] == "DSA-5514-1"]
    assert results
    properties = results[0]["properties"]
    assert properties["severity_source"] == "upstream_cve:CVE-2023-4911"
    assert properties["severity_basis"] == "linked_cve"
    assert properties["severity_linked_cve"] == "CVE-2023-4911"
    assert properties["severity_note"].startswith("Strongest of")


def test_cyclonedx_states_the_linked_cve() -> None:
    entry = _cyclonedx_vulnerability(_linked(), "pkg:deb/debian/libc-bin@2.31-13+deb11u3")

    assert entry["id"] == "DSA-5514-1"
    properties = {item["name"]: item["value"] for item in entry["properties"]}
    assert properties["agent-bom:severity_source"] == "upstream_cve:CVE-2023-4911"
    assert properties["agent-bom:severity_linked_cve"] == "CVE-2023-4911"
    assert properties["agent-bom:severity_note"].startswith("Strongest of")
    assert entry["ratings"][0]["severity"] == "high"
    assert "CVE-2023-4911" in json.dumps(entry["ratings"][0]["source"])


def test_console_badge_names_the_linked_cve() -> None:
    from agent_bom.output.console_style import _finding_sev_badge

    report = _report(_linked())

    assert "via CVE-2023-4911" in _finding_sev_badge(blast_radius_to_finding(report.blast_radii[0]))


def test_api_row_states_the_linked_cve_and_note() -> None:
    from agent_bom.evidence.finding_lanes import lane_response_fields

    fields = lane_response_fields(
        {
            "finding_type": "CVE",
            "evidence": {"severity_source": "upstream_cve:CVE-2023-4911", "severity_note": "Based on 1 of 2 linked CVEs."},
        }
    )

    assert fields["severity_source"] == "upstream_cve:CVE-2023-4911"
    assert fields["severity_linked_cve"] == "CVE-2023-4911"
    assert fields["severity_note"] == "Based on 1 of 2 linked CVEs."


def test_api_row_omits_provenance_a_finding_does_not_have() -> None:
    from agent_bom.evidence.finding_lanes import lane_response_fields

    fields = lane_response_fields({"finding_type": "CVE", "evidence": {"severity_source": "cvss"}})

    assert "severity_linked_cve" not in fields
    assert "severity_note" not in fields


def _summary_only_job(by_severity: dict[str, int], total: int) -> SimpleNamespace:
    return SimpleNamespace(
        result={"summary": {"total_vulnerabilities": total}, "finding_summary": {"by_severity": by_severity, "total": total}},
    )


def test_overview_fallback_gives_no_grade_when_nothing_is_rated(monkeypatch) -> None:
    from agent_bom.api import findings_current, overview_projection

    job = _summary_only_job({"unknown": 20}, 20)
    monkeypatch.setattr(findings_current, "latest_current_scan_job", lambda _jobs, **_kwargs: job)

    snapshot = overview_projection._latest_posture_snapshot([job])

    assert snapshot["grade"] == "N/A"
    assert snapshot["no_data"] is True


def test_overview_fallback_still_grades_rated_findings(monkeypatch) -> None:
    from agent_bom.api import findings_current, overview_projection

    job = _summary_only_job({"medium": 19, "unknown": 1}, 20)
    monkeypatch.setattr(findings_current, "latest_current_scan_job", lambda _jobs, **_kwargs: job)

    assert overview_projection._latest_posture_snapshot([job])["grade"] != "N/A"
