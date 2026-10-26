"""The AI component summary never calls an empty or partial scan "safe"."""

from __future__ import annotations

from types import SimpleNamespace

from rich.console import Console

from agent_bom.cli.agents._discovery_ai import _print_all_safe


def _render(files: int, total: int) -> str:
    console = Console(record=True, width=160)
    report = SimpleNamespace(files_scanned=files, total=total, unique_sdks=set(), unique_models=set())
    _print_all_safe(SimpleNamespace(con=console), report)
    return console.export_text()


def test_zero_files_is_reported_as_nothing_analysed() -> None:
    text = _render(0, 0)
    assert "safe" not in text
    assert "No source files were analysed for AI components" in text


def test_clean_scan_says_what_was_not_found_instead_of_safe() -> None:
    text = _render(12, 3)
    assert "safe" not in text
    assert "12 files scanned — 3 components, no high-risk AI component findings" in text
