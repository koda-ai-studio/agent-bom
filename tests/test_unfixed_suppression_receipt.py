"""Default suppression of unfixed OS advisories leaves a receipt in the summary, the notes and the console."""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest
from rich.console import Console

from agent_bom.cli.agents.scan_pipeline.matching import _print_scan_verdict
from agent_bom.cli.agents.scan_pipeline.report import _build_report
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.output.json_fmt import to_json
from agent_bom.scanners import package_scan, state
from agent_bom.scanners.clean_verdict import suppressed_unfixed_os_findings
from agent_bom.scanners.package_scan import _print_vulnerability_summary, _suppress_unfixed_findings

FLAG = "AGENT_BOM_INCLUDE_UNFIXED=1"


@pytest.fixture(autouse=True)
def _clean_scanner_state(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_INCLUDE_UNFIXED", raising=False)
    monkeypatch.setattr(package_scan, "include_unfixed", False)
    state.reset_scan_warnings()
    state.reset_scan_performance()
    yield
    state.reset_scan_warnings()
    state.reset_scan_performance()


def _unfixed_deb(name: str = "openssl") -> Package:
    return Package(
        name=name,
        version="3.0.17-1~deb12u2",
        ecosystem="deb",
        vulnerabilities=[Vulnerability(id=f"CVE-2026-{abs(hash(name)) % 90000 + 10000}", summary="no-dsa", severity=Severity.HIGH)],
    )


def test_suppression_records_a_scan_note_naming_the_flag_without_marking_coverage_partial():
    con = Console(file=io.StringIO())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", con)
        assert _suppress_unfixed_findings([_unfixed_deb()]) == 1
    notes = [w for w in state.peek_coverage_warnings() if w.get("reason") == "unfixed_os_suppressed"]
    assert len(notes) == 1
    assert notes[0]["kind"] == "scan_note"
    assert "1 unfixed OS-package" in notes[0]["detail"]
    assert FLAG in notes[0]["detail"]
    run = effective_scan_run(SimpleNamespace(agents=[], coverage_warnings=state.peek_coverage_warnings()))
    assert run.outcome is ScanOutcome.COMPLETE


def test_second_suppression_batch_updates_the_receipt_count_instead_of_duplicating_it():
    con = Console(file=io.StringIO())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", con)
        _suppress_unfixed_findings([_unfixed_deb("openssl")])
        _suppress_unfixed_findings([_unfixed_deb("perl"), _unfixed_deb("pam")])
    notes = [w for w in state.peek_coverage_warnings() if w.get("reason") == "unfixed_os_suppressed"]
    assert len(notes) == 1
    assert "3 unfixed OS-package" in notes[0]["detail"]
    assert suppressed_unfixed_os_findings() == 3


def test_scanner_console_never_claims_no_known_vulnerabilities_when_findings_were_suppressed():
    out = io.StringIO()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", Console(file=out, width=200))
        _suppress_unfixed_findings([_unfixed_deb()])
        _print_vulnerability_summary(0, 0)
    text = out.getvalue()
    assert "No known vulnerabilities found" not in text
    assert "No fixable vulnerabilities found; 1 unfixed OS-package finding(s) suppressed" in text
    assert FLAG in text


def test_scanner_console_still_reports_clean_when_nothing_was_suppressed():
    out = io.StringIO()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", Console(file=out, width=200))
        _print_vulnerability_summary(0, 0)
    assert "No known vulnerabilities found" in out.getvalue()


def test_scan_verdict_console_names_the_suppressed_count():
    out = io.StringIO()
    con = Console(file=out, width=200)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", Console(file=io.StringIO()))
        _suppress_unfixed_findings([_unfixed_deb()])
    _print_scan_verdict(SimpleNamespace(offline=False), ScanState(agents=[], con=con), 0)
    text = out.getvalue()
    assert "No known vulnerabilities found" not in text
    assert "1 unfixed OS-package finding(s) suppressed" in text
    assert FLAG in text


@pytest.mark.parametrize("suppressed", [0, 2])
def test_json_summary_carries_the_suppressed_unfixed_count(tmp_path, suppressed):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(package_scan, "console", Console(file=io.StringIO()))
        if suppressed:
            assert _suppress_unfixed_findings([_unfixed_deb("openssl"), _unfixed_deb("perl")]) == suppressed
    st = ScanState(scan_outcome=ScanOutcome.COMPLETE)
    _build_report(SimpleNamespace(project=str(tmp_path)), st)
    document = to_json(st.report)
    assert document["summary"]["suppressed_unfixed_os_findings"] == suppressed
    assert document["summary"]["suppressed_vulnerabilities"] == 0  # operator/VEX suppressions are a different count
