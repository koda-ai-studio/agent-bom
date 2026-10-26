"""A written report's path is printed whole, so it can be copied at any terminal width."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.mark.parametrize(("fmt", "suffix"), [("sarif", ".sarif"), ("json", ".json"), ("cyclonedx", ".cdx.json")])
def test_written_report_path_is_not_wrapped_on_a_narrow_terminal(tmp_path, monkeypatch, fmt, suffix):
    monkeypatch.setenv("COLUMNS", "40")
    out = tmp_path / ("a-deliberately-long-directory-name-" * 3) / f"scan-report{suffix}"
    out.parent.mkdir()
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = CliRunner().invoke(main, ["scan", "--demo", "--exit-zero", "--format", fmt, "--output", str(out), "--no-scan"])

    assert result.exit_code == 0, result.output
    assert out.exists()
    assert str(out) in result.output


def test_cli_written_path_messages_opt_out_of_wrapping():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cli"
    unwrapped = re.compile(r'\.print\(f"[^"]*\{(out_path|output_path|output)\}"\)$')
    offenders = [
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if unwrapped.search(line) and "_con.print" not in line
    ]
    assert offenders == [], "pass soft_wrap=True so the printed path stays copyable: " + ", ".join(offenders)
