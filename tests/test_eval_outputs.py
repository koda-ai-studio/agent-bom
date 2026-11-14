"""Eval suites and the coverage finding through the CLI console, JSON, SARIF and HTML outputs."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.agents._eval_suites_view import eval_summary_lines

_FIXTURES = Path(__file__).parent / "fixtures" / "eval_suites"


def test_console_summary_states_what_was_searched() -> None:
    assert eval_summary_lines([], None) == []
    assert eval_summary_lines([], {"status": "complete", "files_examined": 4}) == [
        "Eval suites: none found in the scanned project files (4 candidate files read)"
    ]
    partial = eval_summary_lines([], {"status": "partial", "detail": "limit reached", "files_examined": 2000})
    assert partial == ["Eval suites: search incomplete (limit reached); eval coverage findings are not raised for this scan"]
    suites = [
        {"harness": "promptfoo", "purpose": "safety", "link_status": "linked"},
        {"harness": "ragas", "purpose": "quality", "link_status": "unlinked"},
    ]
    [line] = eval_summary_lines(suites, {"status": "complete", "files_examined": 2})
    assert "2 found (promptfoo, ragas)" in line and "1 safety, 1 quality, 0 purpose unknown" in line and "1 unlinked" in line


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("eval-outputs") / "uncovered_agent"
    shutil.copytree(_FIXTURES / "uncovered_agent", root)
    for staged in root.rglob("*.fixture"):
        staged.rename(staged.with_suffix(""))
    (root / "requirements.txt").write_text("langchain==1.4.7\n", encoding="utf-8")
    return root


def _run(project: Path, fmt: str, out: Path) -> str:
    args = [
        "scan",
        "-p",
        str(project),
        "--ai-inventory",
        str(project),
        "--offline",
        "--no-discover",
        "--exit-zero",
        "-f",
        fmt,
        "-o",
        str(out),
    ]
    result = CliRunner().invoke(main, args)
    assert out.exists(), result.output
    return result.output


def test_console_prints_the_eval_summary(project: Path, tmp_path: Path) -> None:
    output = _run(project, "json", tmp_path / "r.json")
    assert "Eval suites: 1 found (ragas)" in " ".join(output.split())


def test_sarif_and_html_carry_the_coverage_finding(project: Path, tmp_path: Path) -> None:
    sarif_path, html_path = tmp_path / "r.sarif", tmp_path / "r.html"
    _run(project, "sarif", sarif_path)
    _run(project, "html", html_path)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = [r for run in sarif["runs"] for r in run["results"] if "EVAL_COVERAGE_GAP" in r["ruleId"]]
    assert len(results) == 1
    assert results[0]["level"] == "warning"
    assert results[0]["properties"]["exposed_tools"] == ["run_shell", "write_file"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("ops_agent.py")
    assert "has high-risk capabilities and no linked safety eval" in html_path.read_text(encoding="utf-8")
