"""Scan-run notes explain how evidence was obtained without marking coverage partial."""

from __future__ import annotations

from rich.console import Console

import agent_bom.output.console_render as console_render
from agent_bom.coverage import record_scan_note
from agent_bom.models import AIBOMReport
from agent_bom.output.console_render import print_summary
from agent_bom.output.json_fmt import to_json
from agent_bom.scanners.state import capture_coverage_warnings

_DETAIL = "pyproject.toml: resolved at scan time from declared ranges; versions may differ from your install"


def _note() -> dict:
    with capture_coverage_warnings() as warnings:
        record_scan_note(ecosystem="pypi", path="/src/app/pyproject.toml", reason="resolved_at_scan", detail=_DETAIL)
    [note] = warnings
    return note


def test_note_is_structured_and_distinct_from_a_gap():
    note = _note()
    assert note["kind"] == "scan_note"
    assert note["reason"] == "resolved_at_scan"
    assert note["release"] == "pypi-note:/src/app/pyproject.toml"


def test_note_keeps_the_run_complete_in_json():
    payload = to_json(AIBOMReport(coverage_warnings=[_note()]))
    run = payload["scan_run"]
    assert run["outcome"] == "complete"
    assert [(i["code"], i["affects_coverage"]) for i in run["issues"]] == [("scan_note", False)]


def test_console_prints_notes_outside_the_incomplete_coverage_panel():
    console = Console(record=True, width=160)
    original = console_render._console
    console_render._console = lambda: console  # type: ignore[assignment]
    try:
        print_summary(AIBOMReport(coverage_warnings=[_note()]))
    finally:
        console_render._console = original
    text = console.export_text()
    assert "Incomplete vulnerability coverage" not in text
    assert "resolved at scan time from declared ranges" in text
