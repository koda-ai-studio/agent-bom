"""Execution failure takes precedence over incomplete-coverage rendering."""

from io import StringIO

import pytest
from rich.console import Console

from agent_bom.evidence.scan_run import ScanOutcome, ScanRun
from agent_bom.models import AIBOMReport
from agent_bom.output import print_compact_summary


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize(
    ("outcome", "expected", "unexpected"),
    [
        (ScanOutcome.FAILED, "SCAN FAILED", "PARTIAL COVERAGE"),
        (ScanOutcome.PARTIAL, "PARTIAL COVERAGE", "SCAN FAILED"),
    ],
)
def test_compact_summary_preserves_scan_outcome(monkeypatch, verbose, outcome, expected, unexpected):
    stream = StringIO()
    console = Console(file=stream, width=120, color_system=None)
    monkeypatch.setattr("agent_bom.output.console", console)
    report = AIBOMReport(scan_run=ScanRun(outcome=outcome))

    print_compact_summary(report, verbose=verbose)

    rendered = stream.getvalue()
    assert expected in rendered
    assert unexpected not in rendered
    assert "CLEAN" not in rendered
