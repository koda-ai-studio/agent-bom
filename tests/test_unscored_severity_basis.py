"""Unscored advisories: CVSS, then the advisory's own rating, then distro, then a labelled default."""

from __future__ import annotations

from agent_bom.core.severity import Severity, severity_basis, severity_display_label
from agent_bom.models import BlastRadius, Package, Vulnerability
from agent_bom.scanners.risk import osv_severity_basis


def _ghsa_low_without_cvss() -> dict:
    return {
        "id": "GHSA-h4gh-qq45-vh27",
        "aliases": ["CVE-2024-12797"],
        "summary": "advisory without a CVSS vector",
        "database_specific": {"severity": "LOW", "cwe_ids": []},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "cryptography"}}],
    }


def test_advisory_rating_wins_over_default_when_cvss_is_absent():
    basis = osv_severity_basis(_ghsa_low_without_cvss())
    assert basis.cvss_score is None
    assert basis.severity == Severity.LOW
    assert severity_basis(basis.severity_source) == "advisory"


def test_offline_sync_stores_the_same_advisory_rating():
    basis = osv_severity_basis(_ghsa_low_without_cvss(), advisory_id_fallback=False)
    assert basis.severity == Severity.LOW


def test_distro_qualitative_rating_precedes_default():
    record = {"id": "UBUNTU-CVE-2024-0001", "severity": [{"type": "Ubuntu", "score": "low"}]}
    basis = osv_severity_basis(record)
    assert basis.severity == Severity.LOW
    assert severity_basis(basis.severity_source) == "distro"


def test_record_with_nothing_defaults_to_medium_labelled_unscored():
    basis = osv_severity_basis({"id": "GHSA-xxxx-yyyy-zzzz", "summary": "no rating"})
    assert basis.severity == Severity.MEDIUM
    assert severity_basis(basis.severity_source) == "default"
    assert severity_display_label("medium", basis.severity_source) == "Medium (unscored)"
    assert severity_display_label("medium", "osv_database") == "Medium"


def test_cvss_basis_reported_as_cvss():
    record = {"id": "CVE-2024-1", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    basis = osv_severity_basis(record)
    assert basis.severity == Severity.CRITICAL and severity_basis(basis.severity_source) == "cvss"


def test_finding_and_json_surface_unscored_basis():
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    basis = osv_severity_basis({"id": "PYSEC-2023-175"})
    vuln = Vulnerability(id="PYSEC-2023-175", summary="s", severity=basis.severity, severity_source=basis.severity_source)
    pkg = Package(name="lib", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    br = BlastRadius(vulnerability=vuln, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[])
    finding = blast_radius_to_finding(br)
    assert finding.evidence["severity_basis"] == "default"
    row = to_json(AIBOMReport(agents=[], blast_radii=[br], findings=[finding]))["blast_radius"][0]
    assert row["severity"] == "medium"
    assert row["severity_basis"] == "default"
    assert row["severity_label"] == "medium (unscored)"
