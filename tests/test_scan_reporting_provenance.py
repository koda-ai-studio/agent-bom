"""Scan JSON retains response-cache use and default OS-advisory filtering."""

from types import SimpleNamespace

import pytest

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents.scan_pipeline.report import _attach_context_data, _build_report
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.evidence.scan_run import ScanOutcome
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.output.json_fmt import to_json
from agent_bom.scanners.package_scan import _suppress_unfixed_os_advisories
from agent_bom.scanners.state import _bump_scan_perf, consume_scan_performance, reset_scan_performance
from agent_bom.vuln_freshness import VulnDataFreshness


@pytest.mark.parametrize("queries", [0, 2])
def test_json_reports_warm_osv_response_cache_even_without_local_database(tmp_path, queries):
    reset_scan_performance()
    _bump_scan_perf("osv_cache_hits", 1)
    _bump_scan_perf("osv_queries_sent", queries)
    st = ScanState(
        ctx=ScanContext(con=None),
        scan_outcome=ScanOutcome.COMPLETE,
        vuln_freshness=VulnDataFreshness(mode="live", sources=["OSV", "GHSA", "NVD"]),
    )
    opts = SimpleNamespace(project=str(tmp_path))
    _build_report(opts, st)
    _attach_context_data(opts, st)
    result = to_json(st.report)
    assert result["vuln_data_freshness"]["mode"] == "live-with-cache"
    assert result["vuln_data_freshness"]["osv_response_cache"] == {"packages": 1, "live_queries": queries}
    assert result["vuln_data_freshness"]["age_hours"] is None  # response-cache age is not feed-sync age


def test_linked_cve_request_cost_survives_into_json(tmp_path):
    reset_scan_performance()
    _bump_scan_perf("linked_cve_lookups", 195)
    _bump_scan_perf("linked_cve_cache_hits", 3)
    st = ScanState(scan_outcome=ScanOutcome.COMPLETE)
    _build_report(SimpleNamespace(project=str(tmp_path)), st)
    osv = to_json(st.report)["scan_performance"]["osv"]
    assert osv["linked_cve_lookups"] == 195
    assert osv["linked_cve_cache_hits"] == 3


def test_suppressed_unfixed_count_survives_into_json(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_INCLUDE_UNFIXED", raising=False)
    reset_scan_performance()
    pkg = Package(
        name="openssl",
        version="1.0",
        ecosystem="deb",
        vulnerabilities=[Vulnerability(id="CVE-2026-12345", summary="No upstream fix", severity=Severity.HIGH)],
    )
    assert _suppress_unfixed_os_advisories([pkg]) == 1
    st = ScanState(scan_outcome=ScanOutcome.COMPLETE)
    _build_report(SimpleNamespace(project=str(tmp_path)), st)
    assert to_json(st.report)["scan_performance"]["filtering"]["unfixed_os_findings_suppressed"] == 1
    assert consume_scan_performance()["unfixed_os_findings_suppressed"] == 0


def test_freshness_snapshot_failure_is_logged_not_swallowed(tmp_path, monkeypatch, caplog):
    from agent_bom.cli.agents.scan_pipeline import report as report_stage

    def _broken_summary():
        raise RuntimeError("epss cache unreadable api_key=sk-live-secret")

    monkeypatch.setattr(report_stage, "epss_source_summary", _broken_summary)
    st = ScanState(
        ctx=ScanContext(con=None),
        scan_outcome=ScanOutcome.COMPLETE,
        vuln_freshness=VulnDataFreshness(mode="live", sources=["OSV"]),
    )
    opts = SimpleNamespace(project=str(tmp_path))
    _build_report(opts, st)
    with caplog.at_level("DEBUG", logger="agent_bom.cli.agents.scan_pipeline.report"):
        _attach_context_data(opts, st)

    assert st.report.vuln_data_freshness is None
    messages = [r.getMessage() for r in caplog.records if "freshness snapshot unavailable" in r.getMessage()]
    assert len(messages) == 1
    assert "sk-live-secret" not in messages[0]
