"""A capped metadata-enrichment pass is advisory: reported, never a coverage gap."""

import time
from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from agent_bom.autodiscover import EnrichmentOutcome
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents.scan_pipeline.inventory import _autodiscover_and_drift
from agent_bom.cli.agents.scan_pipeline.report import _build_report, _collect_scan_issues
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.evidence.scan_run import ScanOutcome
from agent_bom.models import Package


def _state() -> ScanState:
    return ScanState(con=Console(file=StringIO(), width=200), ctx=ScanContext(con=None))


def test_capped_enrichment_surfaces_advisory_issue_and_keeps_outcome_complete(tmp_path):
    st = _state()
    st.metadata_enrichment = EnrichmentOutcome(candidates=10_000, cap=30, attempted=30, enriched=30, skipped=9_970)
    opts = SimpleNamespace(no_scan=False, project=str(tmp_path))

    _collect_scan_issues(opts, st)
    _build_report(opts, st)

    issues = [issue for issue in st.report.scan_run.issues if issue.code == "metadata_enrichment_capped"]
    assert len(issues) == 1
    issue = issues[0]
    assert issue.affects_coverage is False
    assert issue.severity == "warning"
    assert issue.stage == "inventory"
    assert "9970" in issue.message or "9,970" in issue.message
    assert "AGENT_BOM_AUTODISCOVER_MAX_CANDIDATES" in issue.message
    assert st.report.scan_run.outcome is ScanOutcome.COMPLETE
    assert st.coverage_warnings == []
    assert st.report.coverage_warnings in ([], None)


def test_uncapped_enrichment_adds_no_issue(tmp_path):
    st = _state()
    st.metadata_enrichment = EnrichmentOutcome(candidates=4, cap=30, attempted=4, enriched=4, skipped=0)
    opts = SimpleNamespace(no_scan=False, project=str(tmp_path))

    _collect_scan_issues(opts, st)

    assert all(issue.code != "metadata_enrichment_capped" for issue in st.scan_issues)


def test_capped_enrichment_does_not_report_failed_lookups_as_fetched(tmp_path):
    st = _state()
    st.metadata_enrichment = EnrichmentOutcome(candidates=10, cap=5, attempted=5, enriched=2, skipped=5)
    _collect_scan_issues(SimpleNamespace(no_scan=False, project=str(tmp_path)), st)
    issue = next(issue for issue in st.scan_issues if issue.code == "metadata_enrichment_capped")
    assert "attempted for 5 of 10" in issue.message
    assert "2 enriched" in issue.message


def test_autodiscover_stage_records_outcome_and_prints_cap_line(monkeypatch):
    st = _state()
    st.all_packages = [Package(name=f"p{i}", version="1.0.0", ecosystem="npm", resolved_from_registry=False) for i in range(12)]
    st.step_t0 = time.monotonic()
    opts = SimpleNamespace(no_scan=False, offline=False, quiet=False)
    seen: dict[str, int] = {}

    async def _fake_enrich(packages, **_kwargs):
        seen["count"] = len(packages)
        return EnrichmentOutcome(candidates=len(packages), cap=5, attempted=5, enriched=4, skipped=len(packages) - 5)

    monkeypatch.setattr("agent_bom.autodiscover.enrich_unknown_packages", _fake_enrich)

    _autodiscover_and_drift(opts, st)

    assert seen["count"] == 12
    assert st.metadata_enrichment.skipped == 7
    text = st.con.file.getvalue()
    assert "Auto-discovered metadata for 4 package(s)" in text
    assert "7" in text and "not enriched" in text
