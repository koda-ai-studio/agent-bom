"""Cross-release OS matches are candidates, not confirmed vulnerable versions."""

from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Package
from agent_bom.scanners.package_check_result import has_lookup_coverage_gap
from agent_bom.scanners.package_scan import scan_packages
from agent_bom.scanners.state import consume_coverage_warnings


@pytest.fixture
def advisory_lookup(monkeypatch, tmp_path):
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", tmp_path / "missing.db")
    monkeypatch.setattr("agent_bom.scanners.local_data_freshness.freshness_snapshot", lambda _: None)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda _: False)

    async def query(packages):
        from agent_bom.scanners.state import _bump_scan_perf

        _bump_scan_perf("osv_batches_answered", 1)
        return {
            f"{pkg.ecosystem}:{pkg.name}@{pkg.version}": [
                {
                    "id": "DEBIAN-CVE-2026-41991",
                    "aliases": ["CVE-2026-41991"],
                    "summary": "Distro-scoped fixture",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"name": "gzip", "ecosystem": "Debian:12"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.14-1"}]}],
                        }
                    ],
                }
            ]
            for pkg in packages
        }

    monkeypatch.setattr("agent_bom.scanners.query_osv_batch", query)


@pytest.mark.parametrize("include_unfixed", ["0", "1"])
def test_unknown_release_keeps_candidate_and_coverage_gap(advisory_lookup, monkeypatch, include_unfixed):
    monkeypatch.setenv("AGENT_BOM_INCLUDE_UNFIXED", include_unfixed)
    pkg = Package(name="gzip", version="1.13-1+deb13u1", ecosystem="deb")
    count = asyncio.run(scan_packages([pkg]))
    assert count == 0
    assert pkg.vulnerabilities == []
    assert len(pkg.possibly_affected) == 1
    candidate = pkg.possibly_affected[0]
    assert candidate["id"] == "CVE-2026-41991"
    assert candidate["reason"] == "ambiguous_distro_release"
    assert candidate.get("fixed_version") is None
    warnings = consume_coverage_warnings()
    assert any(row["kind"] == "distro_release_gap" for row in warnings)
    assert has_lookup_coverage_gap(warnings)


@pytest.mark.parametrize("extra", [[], ["--exit-zero"], ["--fail-on-severity", "critical"]])
def test_check_unknown_release_is_incomplete_not_unsafe(advisory_lookup, extra):
    result = CliRunner().invoke(main, ["check", "gzip@1.13-1+deb13u1", "-e", "deb", "-f", "json", *extra])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["canonical_verdict"] == "incomplete"
    assert payload["vulnerability_count"] == 0
    assert payload["completeness"]["status"] == "incomplete"
    assert payload["possibly_affected"][0]["id"] == "CVE-2026-41991"


def test_release_scoped_match_remains_confirmed(advisory_lookup):
    pkg = Package(name="gzip", version="1.13-1", ecosystem="deb", distro_name="debian", distro_version="12")
    assert asyncio.run(scan_packages([pkg])) == 1
    assert pkg.vulnerabilities[0].fixed_version == "1.14-1"
    assert pkg.possibly_affected == []


def test_other_release_advisory_does_not_become_a_match(advisory_lookup):
    pkg = Package(name="gzip", version="1.13-1+deb13u1", ecosystem="deb", distro_name="debian", distro_version="13")
    assert asyncio.run(scan_packages([pkg])) == 0
    assert pkg.vulnerabilities == []
    assert pkg.possibly_affected == []


def test_service_check_retains_candidate_evidence(advisory_lookup):
    from agent_bom.mcp_tools.scanning import check_impl

    raw = asyncio.run(
        check_impl(
            package="gzip",
            ecosystem="deb",
            version="1.13-1+deb13u1",
            _validate_ecosystem=lambda value: value,
            _truncate_response=lambda value: value,
        )
    )
    payload = json.loads(raw)
    assert payload["canonical_verdict"] == "incomplete"
    assert payload["vulnerability_count"] == 0
    assert payload["completeness"]["status"] == "incomplete"
    assert payload["possibly_affected"][0]["id"] == "CVE-2026-41991"


def test_sarif_check_retains_candidate_evidence(advisory_lookup):
    result = CliRunner().invoke(main, ["check", "gzip@1.13-1+deb13u1", "-e", "deb", "-f", "sarif"])
    assert result.exit_code == 2, result.output
    run = json.loads(result.stdout)["runs"][0]
    assert run["results"] == []
    assert run["properties"]["completeness"]["status"] == "incomplete"
    assert run["properties"]["possibly_affected"][0]["id"] == "CVE-2026-41991"


def test_scan_report_records_gap_and_retains_candidates(advisory_lookup):
    from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
    from agent_bom.output import to_json

    pkg = Package(name="gzip", version="1.13-1+deb13u1", ecosystem="deb")
    asyncio.run(scan_packages([pkg]))
    report = AIBOMReport(
        agents=[
            Agent(name="target", agent_type=AgentType.CUSTOM, config_path="fixture", mcp_servers=[MCPServer(name="target", packages=[pkg])])
        ],
        coverage_warnings=consume_coverage_warnings(),
    )
    assert effective_scan_run(report).outcome != ScanOutcome.COMPLETE
    assert to_json(report)["possibly_affected"][0]["id"] == "CVE-2026-41991"
