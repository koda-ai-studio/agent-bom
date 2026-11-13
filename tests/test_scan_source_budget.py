"""The default scan stops source analysis at a budget and says so; --full-analysis covers everything.

The fixture is a generated repository of a few thousand small files. Assertions
count work done (files analysed, files scanned) rather than wall time, plus one
generous wall-time bound so a regression to quadratic work still fails.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.scan_budget import DEFAULT_SOURCE_BUDGET

_PY = 1_700
_JS = 900
_SERVER = (
    'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("demo")\n\n\n'
    '@mcp.tool()\ndef ping(text: str) -> str:\n    """Echo."""\n    return text\n'
)


@pytest.fixture(scope="module")
def generated_repo(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("budget-repo")
    for index in range(_PY):
        package = root / "app" / f"pkg{index // 100:02d}"
        package.mkdir(parents=True, exist_ok=True)
        (package / f"mod{index:04d}.py").write_text(f"def handler_{index}(value):\n    return value + {index}\n")
    for index in range(_JS):
        folder = root / "web" / f"part{index // 100:02d}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"view{index:04d}.js").write_text(f"export function view{index}(x) {{ return x + {index}; }}\n")
    (root / "server.py").write_text(_SERVER)
    (root / "requirements.txt").write_text("requests==2.32.3\n")
    return root


def _scan(repo: Path, out: Path, *extra: str) -> tuple[dict, str, float]:
    from agent_bom.cli import main

    started = time.monotonic()
    result = CliRunner().invoke(
        main,
        ["scan", str(repo), "--no-scan", "--offline", "--no-auto-update-db", "-f", "json", "-o", str(out), *extra],
        catch_exceptions=False,
    )
    elapsed = time.monotonic() - started
    assert out.exists(), result.output
    return json.loads(out.read_text()), result.output, elapsed


def _issue_text(report: dict) -> str:
    return json.dumps(report["scan_run"].get("issues", [])) + json.dumps(report.get("coverage_warnings", []))


def test_default_scan_stops_at_the_budget_and_reports_it_incomplete(generated_repo, tmp_path):
    report, output, elapsed = _scan(generated_repo, tmp_path / "default.json")

    analysis = report["ai_inventory"]["ast_analysis"]["analysis_coverage"]
    assert analysis["eligible_files"] == _PY + _JS + 1
    assert analysis["analyzed_files"] == DEFAULT_SOURCE_BUDGET.code_analysis_files
    assert analysis["status"] == "partial"

    secrets = report["ai_inventory"]["secrets"]
    assert secrets["files_scanned"] == DEFAULT_SOURCE_BUDGET.secret_files
    assert secrets["complete"] is False

    assert report["ai_inventory"]["files_scanned"] == DEFAULT_SOURCE_BUDGET.ai_component_files

    issues = _issue_text(report)
    assert issues.count("--full-analysis") >= 3
    assert report["scan_run"]["outcome"] != "complete"
    assert "CLEAN" not in output
    console = " ".join(output.split())
    assert "Source analysis stopped at the default scan budget" in console
    assert "--full-analysis" in console
    assert elapsed < 180


def test_full_analysis_covers_every_file(generated_repo, tmp_path):
    report, _output, elapsed = _scan(generated_repo, tmp_path / "full.json", "--full-analysis")

    analysis = report["ai_inventory"]["ast_analysis"]["analysis_coverage"]
    assert analysis["analyzed_files"] == analysis["eligible_files"] == _PY + _JS + 1
    secrets = report["ai_inventory"].get("secrets")
    # A complete secret scan with no findings writes no section; a partial one always does.
    assert secrets is None or (secrets["complete"] is True and secrets["files_scanned"] > DEFAULT_SOURCE_BUDGET.secret_files)
    assert report["ai_inventory"]["files_scanned"] == _PY + _JS + 1
    assert "--full-analysis" not in _issue_text(report)
    assert "default scan budget" not in " ".join(_output.split())
    assert elapsed < 300


def test_budget_selection_is_deterministic(generated_repo, tmp_path):
    first, _, _ = _scan(generated_repo, tmp_path / "a.json")
    second, _, _ = _scan(generated_repo, tmp_path / "b.json")

    assert first["ai_inventory"]["secrets"]["files_scanned"] == second["ai_inventory"]["secrets"]["files_scanned"]
    assert first["ai_inventory"]["ast_analysis"]["stats"] == second["ai_inventory"]["ast_analysis"]["stats"]


def test_small_project_is_not_affected_by_the_budget(tmp_path):
    repo = tmp_path / "small"
    (repo / "app").mkdir(parents=True)
    for index in range(19):
        (repo / "app" / f"m{index}.py").write_text(f"def f{index}():\n    return {index}\n")
    (repo / "server.py").write_text(_SERVER)

    report, _output, _elapsed = _scan(repo, tmp_path / "small.json")

    analysis = report["ai_inventory"]["ast_analysis"]["analysis_coverage"]
    assert analysis["analyzed_files"] == analysis["eligible_files"] == 20
    assert "--full-analysis" not in _issue_text(report)
