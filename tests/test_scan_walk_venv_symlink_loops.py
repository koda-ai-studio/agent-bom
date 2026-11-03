"""Walking a developer checkout must not turn venvs and symlink loops into coverage gaps.

A virtualenv under any name (``env``, ``.venv-3.12``, ``myenv``) holds
``bin/python`` symlinks out of the tree, and checkouts often carry symlink
loops. Both were recorded as coverage gaps, so a plain ``agent-bom scan`` of
the working directory was "partial" and exited 1. Symlinks whose target is
inside the root (already walked by its real path) or that resolve nowhere
(loops, dangling) hide no content: they are scope exclusions. A symlink out of
the root still hides content and stays a coverage gap.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.coverage import SCOPE_EXCLUSION_REASONS
from agent_bom.parsers import scan_project_directory
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings
from agent_bom.secret_scanner import scan_secrets
from agent_bom.traversal import iter_discovery_files


def _checkout_with_venv_and_loops(tmp_path: Path) -> tuple[Path, Path]:
    outside = tmp_path / "interpreter"
    outside.mkdir()
    (outside / "python3").write_text("#!binary\n")
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("print('hi')\n")
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    venv = root / "myenv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (venv / "bin" / "python").symlink_to(outside / "python3")
    (venv / "lib" / "site").mkdir(parents=True)
    (venv / "lib" / "site" / "requirements.txt").write_text("flask==0.1\n")
    (root / "app" / "self").symlink_to(root / "app", target_is_directory=True)
    (root / "loop").symlink_to(root / "loop")
    (root / "a").symlink_to(root / "b")
    (root / "b").symlink_to(root / "a")
    (root / "dangling").symlink_to(root / "missing")
    return root, outside


def test_venv_and_loops_are_scope_exclusions_not_coverage_gaps(tmp_path: Path) -> None:
    root, _outside = _checkout_with_venv_and_loops(tmp_path)
    reset_scan_warnings()
    try:
        files = sorted(p.relative_to(root).as_posix() for p in iter_discovery_files(root))
        warnings = consume_coverage_warnings()
    finally:
        reset_scan_warnings()
    assert files == ["app/main.py", "requirements.txt"]
    gaps = [w for w in warnings if w["kind"] == "coverage_gap"]
    assert gaps == []
    reasons = {w["reason"] for w in warnings}
    assert {"directory_policy", "symlink_within_root", "broken_symlink"} <= reasons
    assert reasons <= SCOPE_EXCLUSION_REASONS


def test_symlink_out_of_root_is_still_a_coverage_gap(tmp_path: Path) -> None:
    root, outside = _checkout_with_venv_and_loops(tmp_path)
    (root / "app" / "linked.py").symlink_to(outside / "python3")
    reset_scan_warnings()
    try:
        list(iter_discovery_files(root))
        warnings = consume_coverage_warnings()
    finally:
        reset_scan_warnings()
    assert any(w["reason"] == "file_symlink" and w["kind"] == "coverage_gap" for w in warnings)


def test_secret_scan_of_checkout_is_complete(tmp_path: Path) -> None:
    root, _outside = _checkout_with_venv_and_loops(tmp_path)
    result = scan_secrets(root)
    assert result.warnings == []
    assert result.to_dict()["complete"] is True
    assert result.files_scanned == 2


def test_project_walk_skips_any_virtualenv(tmp_path: Path) -> None:
    root, _outside = _checkout_with_venv_and_loops(tmp_path)
    warnings: list[str] = []
    found = scan_project_directory(root, warnings=warnings)
    assert [d.relative_to(root).as_posix() for d in found] == ["."]
    assert {p.name for p in found[root]} == {"requests"}
    assert not any("myenv" in w for w in warnings)
