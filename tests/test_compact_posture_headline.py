"""The summary panel shows the posture headline whole; its drivers are on the next line, never cut mid-sentence."""

from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cli import main


def test_demo_summary_posture_line_is_not_truncated() -> None:
    result = CliRunner().invoke(main, ["scan", "--demo", "--offline", "--format", "console", "--exit-zero"], env={"COLUMNS": "120"})
    grade_lines = [line for line in result.output.splitlines() if "Posture grade:" in line]
    assert grade_lines, result.output
    assert "…" not in grade_lines[0]
    assert "this grade is driven by" not in grade_lines[0]
