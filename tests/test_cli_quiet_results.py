"""``-q`` drops progress and banners but never the result itself."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main

_PROGRESS_MARKERS = ("Discovering", "Package Extraction", "Vulnerability Scan", "Scan Complete", "Exit-code contract")


def _invoke(args: list[str]):
    return CliRunner().invoke(main, args)


def test_quiet_console_scan_prints_verdict_counts_and_exit_reason() -> None:
    result = _invoke(["scan", "--demo", "--offline", "-q", "--fail-on-severity", "high"])

    assert result.exit_code == 1
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines, "quiet scan printed nothing"
    assert lines[0].startswith("agent-bom: FAIL"), lines[0]
    assert "critical" in lines[0] and "high" in lines[0]
    assert any(line.startswith("Exit 1: found critical vulnerability (CVE-") for line in lines), lines
    for marker in _PROGRESS_MARKERS:
        assert marker not in result.output
    assert len(lines) <= 4, lines


def test_quiet_scan_that_passes_reports_pass_and_exit_zero() -> None:
    result = _invoke(["scan", "--demo", "--offline", "-q", "--exit-zero"])

    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[0].startswith("agent-bom: PASS"), lines
    assert not any(line.startswith("Exit 1") for line in lines)


def test_quiet_scan_with_report_file_names_where_it_was_written(tmp_path: Path) -> None:
    out = tmp_path / "r.json"

    result = _invoke(["scan", "--demo", "--offline", "-q", "-f", "json", "-o", str(out), "--exit-zero"])

    assert result.exit_code == 0
    assert out.is_file()
    assert f"Report: {out}" in result.stdout
    assert "agent-bom: PASS" in result.stdout
    assert "Top fixes (" not in result.output


def test_quiet_json_on_stdout_stays_parseable_and_summary_goes_to_stderr() -> None:
    result = _invoke(["scan", "--demo", "--offline", "-q", "-f", "json", "--fail-on-severity", "high"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["document_type"] == "AI-BOM"
    assert "agent-bom: FAIL" in result.stderr
    assert "Exit 1: found critical vulnerability" in result.stderr


def test_quiet_agent_mode_envelope_is_unchanged() -> None:
    result = _invoke(["scan", "--agent-mode", "--demo", "--offline", "--exit-zero"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["document_type"] == "AI-BOM"
    assert "agent-bom: PASS" not in result.output


def test_quiet_partial_scan_names_the_partial_reason(tmp_path: Path) -> None:
    from unittest.mock import patch

    from agent_bom.evidence.scan_run import ScanOutcome

    with patch("agent_bom.cli.agents._post._execution_outcome", return_value=ScanOutcome.PARTIAL):
        result = _invoke(["scan", "--demo", "--offline", "-q"])

    assert result.exit_code == 1
    assert "Exit 1: scan execution was partial" in result.stdout


def test_quiet_fs_forwards_to_the_same_summary(tmp_path: Path) -> None:
    from unittest.mock import patch

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    with patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]):
        result = _invoke(["fs", str(tmp_path), "-q"])

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines and lines[0].startswith("agent-bom: "), result.output


def test_quiet_incomplete_scan_names_why_it_stopped(tmp_path: Path) -> None:
    from unittest.mock import patch

    from agent_bom.scanners.scan_options import IncompleteScanError

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    error = IncompleteScanError("Offline mode requires a populated local vulnerability DB.")

    with patch("agent_bom.cli.agents.scan_agents_sync", side_effect=error):
        result = _invoke(["scan", "-p", str(tmp_path), "--offline", "-q"])

    assert result.exit_code == 1
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[0].startswith("agent-bom: FAIL — incomplete scan"), result.output
    assert "Exit 1: Offline mode requires a populated local vulnerability DB." in lines


def test_quiet_code_prints_a_result_line(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('import openai\nSYSTEM_PROMPT = "You are helpful " + user_input\n', encoding="utf-8")

    result = _invoke(["code", str(tmp_path), "-q"])

    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, result.output
    assert lines[0].startswith("agent-bom code: ") and "files analyzed" in lines[0]


def test_quiet_secrets_prints_findings_and_total(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('GITHUB_TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n', encoding="utf-8")

    result = _invoke(["secrets", str(tmp_path), "-q"])

    assert "Secret scan:" not in result.output
    assert "findings" in result.stdout, result.output


def test_quiet_code_json_to_file_names_the_report(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import openai\n", encoding="utf-8")
    out = tmp_path / "code.json"

    result = _invoke(["code", str(tmp_path), "-q", "-f", "json", "-o", str(out)])

    assert result.exit_code == 0
    assert out.is_file()
    assert result.stdout.strip() == f"Report: {out}"


def test_quiet_mcp_inventory_prints_counts() -> None:
    result = _invoke(["mcp", "inventory", "--demo", "-q"])

    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, result.output
    assert lines[0].startswith("agent-bom inventory: ") and "agent(s)" in lines[0] and "MCP server(s)" in lines[0]


def test_scan_short_help_shows_the_everyday_flags() -> None:
    help_text = _invoke(["scan", "--help"]).output
    short = help_text[: help_text.index("More options:")]

    for flag in ("--quick", "--full-analysis", "-q, --quiet", "--log-json", "-f, --format", "-o, --output", "--fail-on-severity"):
        assert flag in short, flag
    assert "--jira-token" not in help_text


def test_quiet_help_text_describes_the_summary() -> None:
    help_text = " ".join(_invoke(["scan", "--help"]).output.split())

    assert "Suppress all output except results" not in help_text
    assert "-q, --quiet" in help_text
    assert "verdict" in help_text


def test_quiet_summary_names_an_inferred_format_report_path(monkeypatch, tmp_path):
    """image -o report.json without -f infers JSON from the extension; -q must name that file."""
    from click.testing import CliRunner

    from agent_bom.cli import main
    from agent_bom.models import Package

    output = tmp_path / "image-report.json"
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref, registry_user=None, registry_pass=None, platform=None, pull_mode=None: (
            [Package(name="openssl", version="3.0.16", ecosystem="deb")],
            "native",
        ),
    )
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", lambda *args, **kwargs: [])

    result = CliRunner().invoke(main, ["image", "nginx:1.20.0", "-o", str(output), "--quiet"])

    assert result.exit_code == 0, result.output
    assert output.exists()
    assert f"Report: {output}" in result.output
