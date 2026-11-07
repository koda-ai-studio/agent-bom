"""Distro fix advisories retain CVE relationships without duplicate findings."""

from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.scanners.advisory_merge import merge_advisory_clusters
from agent_bom.scanners.state import peek_scan_warnings, reset_scan_warnings
from agent_bom.scanners.upstream_severity import resolve_upstream_advisory_severity


def advisory():
    return Vulnerability(
        id="DSA-1234-1",
        summary="Security update",
        severity=Severity.UNKNOWN,
        upstream_ids=["CVE-2024-1234", "CVE-2024-1235"],
        fixed_version="2.0",
        references=["https://security-tracker.debian.org/tracker/DSA-1234-1"],
    )


def test_unknown_distro_severity_is_explicit_without_local_database(tmp_path):
    reset_scan_warnings()
    vuln = advisory()
    package = Package(name="libexample", version="1.0", ecosystem="deb", vulnerabilities=[vuln])
    assert resolve_upstream_advisory_severity([package], db_path=tmp_path / "missing.db") == 0
    assert vuln.severity is Severity.UNKNOWN
    assert any("severity is missing" in message.lower() for message in peek_scan_warnings())
    finding = blast_radius_to_finding(
        BlastRadius(vulnerability=vuln, package=package, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[])
    )
    assert finding.evidence["cve_ids"] == ["CVE-2024-1234", "CVE-2024-1235"]
    assert not vuln.aliases  # A fix relationship is not an identity alias.


def test_distro_rollup_collapses_only_when_all_cves_and_fixes_are_represented():
    cves = [
        Vulnerability(id=identifier, summary="CVE", severity=Severity.HIGH, fixed_version="2.0") for identifier in advisory().upstream_ids
    ]
    merged = merge_advisory_clusters([advisory(), *cves])
    assert [row.id for row in merged] == [row.id for row in cves]
    assert all(advisory().references[0] in row.references for row in merged)
    assert len(merge_advisory_clusters([advisory(), cves[0]])) == 2
    cves[0].fixed_version = "3.0"
    assert len(merge_advisory_clusters([advisory(), *cves])) == 3
