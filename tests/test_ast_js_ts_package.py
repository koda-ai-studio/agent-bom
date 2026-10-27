"""Contract tests for the public JS/TS analysis package."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest


def test_js_ts_parser_runtime_is_installed_by_the_base_package() -> None:
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = {dependency.split(">=", 1)[0] for dependency in project["dependencies"]}

    assert {
        "tree-sitter",
        "tree-sitter-javascript",
        "tree-sitter-typescript",
    }.issubset(dependencies)


def test_package_exposes_facade_entry_points():
    from agent_bom.ast import js_ts
    from agent_bom.ast.js_ts import facade

    assert js_ts.scan_js_ts_file is facade.scan_js_ts_file
    assert js_ts.build_js_ts_flow_findings is facade.build_js_ts_flow_findings
    assert js_ts.build_js_ts_dependency_symbol_reach is facade.build_js_ts_dependency_symbol_reach
    assert js_ts.JS_TS_EXTS is facade._JS_TS_EXTS
    assert js_ts.js_ts_function_key is facade._js_ts_function_key
    assert js_ts.npm_package_from_module is facade._npm_package_from_module


def test_package_exposes_engine_entry_points():
    from agent_bom.ast import js_ts
    from agent_bom.ast.js_ts import engine

    assert js_ts.analyze_js_ts_block is engine.analyze_js_ts_block
    assert js_ts.JSTSAstUnavailableError is engine.JSTSAstUnavailableError
    assert js_ts.JSTSAstAnalysis is engine.JSTSAstAnalysis
    assert js_ts.JSTSFunction is engine.JSTSFunction
    assert js_ts.JSTSToolRegistration is engine.JSTSToolRegistration
    assert js_ts.JSImportRef is engine.JSImportRef
    assert js_ts.JSTSCallSite is engine.JSTSCallSite


def test_package_declares_public_api():
    from agent_bom.ast import js_ts

    assert set(js_ts.__all__) >= {
        "scan_js_ts_file",
        "build_js_ts_flow_findings",
        "build_js_ts_dependency_symbol_reach",
        "analyze_js_ts_block",
        "JSTSAstUnavailableError",
    }


def test_scan_degrades_to_regex_when_engine_unavailable(tmp_path, monkeypatch):
    from agent_bom.ast.js_ts import JSTSAstUnavailableError, engine, scan_js_ts_file
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    reset_scan_warnings()

    def _unavailable(source: str, *, language_hint: str = "javascript"):
        raise JSTSAstUnavailableError("forced unavailable for fallback test")

    monkeypatch.setattr(engine, "analyze_js_ts_block", _unavailable)
    sample = tmp_path / "tool.js"
    sample.write_text('const cp = require("child_process");\ncp.execSync(userInput);\n', encoding="utf-8")

    _prompts, _guardrails, _tools, findings, _frameworks, _edges, analysis = scan_js_ts_file(sample, "tool.js")

    assert analysis is None
    assert any(finding.category == "js_ts_dangerous_call" for finding in findings)
    assert consume_coverage_warnings() == [
        {
            "ecosystem": "ast-js-ts",
            "release": "ast-js-ts:tool.js",
            "reason": "ast_engine_unavailable",
            "detail": "Structured JS/TS analysis did not complete; regex fallback coverage is partial.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]


@pytest.mark.parametrize("legacy", ["agent_bom.ast_js_ts", "agent_bom.js_ts_ast"])
def test_legacy_js_ts_module_paths_are_removed(legacy: str) -> None:
    """The deprecated shims are gone; agent_bom.ast.js_ts is the only import path."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(legacy)
