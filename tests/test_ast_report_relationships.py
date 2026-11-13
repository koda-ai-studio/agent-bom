"""Code-analysis relationship rows are counted by default and listed only on request."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from click.testing import CliRunner

from agent_bom.ast_analyzer import analyze_project

_SCHEMA = Path(__file__).resolve().parents[1] / "contracts" / "v1" / "scan-report.schema.json"
_RELATIONSHIP_LISTS = ("call_graph", "cfg_edges", "dependency_symbol_reach")
_STATS = {"call_graph": "total_call_edges", "cfg_edges": "total_cfg_edges", "dependency_symbol_reach": "total_dependency_symbol_reach"}

_SOURCE = '''
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def helper(cmd):
    if cmd:
        return subprocess.run(cmd, shell=True)
    return None


@mcp.tool()
def run(cmd: str) -> str:
    """Run a command."""
    helper(cmd)
    return "ok"
'''


def _project(tmp_path: Path) -> Path:
    (tmp_path / "server.py").write_text(_SOURCE)
    (tmp_path / "requirements.txt").write_text("mcp==1.2.0\n")
    return tmp_path


def test_full_dict_keeps_every_relationship_row_and_its_counts(tmp_path):
    result = analyze_project(_project(tmp_path))

    full = result.to_dict()

    assert full["relationships_included"] is True
    for key, stat in _STATS.items():
        assert full["stats"][stat] == len(full[key]), key
    assert full["stats"]["total_cfg_edges"] > 0
    assert full["stats"]["total_call_edges"] > 0


def test_summary_dict_replaces_rows_with_counts_not_empty_lists(tmp_path):
    result = analyze_project(_project(tmp_path))

    full = result.to_dict()
    summary = result.to_dict(include_relationships=False)

    for key in _RELATIONSHIP_LISTS:
        assert key not in summary
    assert summary["relationships_included"] is False
    for key in set(full) - set(_RELATIONSHIP_LISTS) - {"relationships_included"}:
        assert summary[key] == full[key], key


def _scan_json(tmp_path: Path, *extra: str) -> dict:
    from agent_bom.cli import main

    project = _project(tmp_path / "proj")
    out = tmp_path / f"report{len(extra)}.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-scan", "--offline", "--no-auto-update-db", "-f", "json", "-o", str(out), *extra],
        catch_exceptions=False,
    )
    assert out.exists(), result.output
    return json.loads(out.read_text())


def test_cli_json_report_counts_relationships_by_default(tmp_path):
    (tmp_path / "proj").mkdir()
    report = _scan_json(tmp_path)

    analysis = report["ai_inventory"]["ast_analysis"]
    assert analysis["relationships_included"] is False
    assert analysis["stats"]["total_cfg_edges"] > 0
    assert not any(key in analysis for key in _RELATIONSHIP_LISTS)
    jsonschema.validate(report, json.loads(_SCHEMA.read_text()))


def test_cli_json_report_lists_relationships_when_asked(tmp_path):
    (tmp_path / "proj").mkdir()
    report = _scan_json(tmp_path, "--include-code-graph")

    analysis = report["ai_inventory"]["ast_analysis"]
    assert analysis["relationships_included"] is True
    assert len(analysis["cfg_edges"]) == analysis["stats"]["total_cfg_edges"] > 0
    jsonschema.validate(report, json.loads(_SCHEMA.read_text()))
