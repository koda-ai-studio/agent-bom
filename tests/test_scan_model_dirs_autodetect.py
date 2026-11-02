"""Model binaries in a project are scanned by default; the quick preset gets a hint instead.

``--no-discover`` controls MCP host discovery and must not silence the model
file surface; the detection walk is the shared pruned traversal, so vendored
``node_modules``/``.venv`` trees are never scanned.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from agent_bom.cli.agents.scan_pipeline.late import _detect_model_dirs
from agent_bom.repo_auto_detect import detect_tree_surfaces


def _opts(project: Path, **overrides):
    base = {"skill_only": False, "no_discover": True, "model_dirs": (), "project": str(project), "preset": None}
    base.update(overrides)
    return SimpleNamespace(**base)


def _state():
    return SimpleNamespace(con=Console(record=True, width=200, force_terminal=False))


def test_model_files_enable_the_surface_even_with_no_discover(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "clf.pkl").write_bytes(b"\x80\x04.")
    opts, st = _opts(tmp_path), _state()

    _detect_model_dirs(opts, st)

    assert opts.model_dirs == (str(tmp_path),)
    assert "model file" in st.con.export_text().lower()


def test_quick_preset_hints_instead_of_scanning(tmp_path: Path) -> None:
    (tmp_path / "w.safetensors").write_bytes(b"\x00" * 8)
    opts, st = _opts(tmp_path, preset="quick"), _state()

    _detect_model_dirs(opts, st)

    assert opts.model_dirs == ()
    text = st.con.export_text()
    assert "--model-files" in text and "not scanned" in text


def test_vendored_trees_do_not_trigger_the_surface(tmp_path: Path) -> None:
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "weights.onnx").write_bytes(b"\x00")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "model.pt").write_bytes(b"\x00")
    (tmp_path / "README.md").write_text("no models here\n")
    opts, st = _opts(tmp_path), _state()

    assert detect_tree_surfaces(tmp_path, frozenset({"model_files"})) == frozenset()
    _detect_model_dirs(opts, st)
    assert opts.model_dirs == ()


def test_explicit_model_dirs_and_skill_only_are_left_alone(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(b"GGUF")
    explicit, st = _opts(tmp_path, model_dirs=("/elsewhere",)), _state()
    _detect_model_dirs(explicit, st)
    assert explicit.model_dirs == ("/elsewhere",)

    skill, st = _opts(tmp_path, skill_only=True), _state()
    _detect_model_dirs(skill, st)
    assert skill.model_dirs == ()
