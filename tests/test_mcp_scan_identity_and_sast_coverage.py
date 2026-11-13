"""MCP ``scan`` results carry a real scan id, and a skipped SAST pass is a coverage warning."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api.repo_tree_scan import RepoTreeScanResult, _scan_sast_stage
from agent_bom.mcp_tools.scan_report import build_scan_report
from agent_bom.models import AIBOMReport
from agent_bom.sast import SASTExecutionStatus, SASTScanError
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings


def test_mcp_scan_report_has_a_scan_id() -> None:
    first = build_scan_report(AIBOMReport, [], [], ["agent_discovery"], offline=True)
    second = build_scan_report(AIBOMReport, [], [], ["agent_discovery"], offline=True)
    assert first.scan_id and second.scan_id
    assert first.scan_id != second.scan_id


def test_skipped_sast_is_recorded_as_a_coverage_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "server.py").write_text("print('hi')\n")

    def unavailable(*_args, **_kwargs):
        raise SASTScanError("no semgrep", execution_status=SASTExecutionStatus.SKIPPED, reason_code="semgrep_unavailable")

    monkeypatch.setattr("agent_bom.sast.scan_code", unavailable)
    reset_scan_warnings()
    warnings: list[str] = []
    _scan_sast_stage(tmp_path, RepoTreeScanResult(), [], warnings, None, False)
    assert warnings == ["SAST skipped: semgrep_unavailable"]
    coverage = consume_coverage_warnings()
    assert [item["reason"] for item in coverage] == ["semgrep_unavailable"]
    assert coverage[0]["ecosystem"] == "sast"
    assert "Semgrep is unavailable" in coverage[0]["detail"]
