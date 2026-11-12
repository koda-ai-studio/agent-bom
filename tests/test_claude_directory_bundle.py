"""The directory ships only Claude runtime inputs, without changing local Codex."""

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_claude_directory_is_a_standalone_copy_of_runtime_inputs():
    source = ROOT / "integrations/claude-code"
    bundle = ROOT / "integrations/claude-directory"
    expected = {
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "mcp_launcher.py",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "assets/icon.png",
        *(str(path.relative_to(source)) for path in (source / "skills").glob("*/SKILL.md")),
    }
    actual = {str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()}
    assert actual == expected
    for name in expected - {"README.md"}:
        assert (bundle / name).read_bytes() == (source / name).read_bytes()
    assert (source / ".codex-plugin/plugin.json").is_file()
    assert not (bundle / ".codex-plugin").exists()


def test_bundle_guard_detects_changed_and_extra_files(tmp_path):
    builder = runpy.run_path(str(ROOT / "scripts/build_claude_directory.py"))
    (tmp_path / "expected.txt").write_bytes(b"changed")
    (tmp_path / "unexpected.txt").write_bytes(b"extra")
    assert builder["stale_files"](tmp_path, {"expected.txt": b"original"}) == ["expected.txt", "unexpected.txt"]


def test_committed_bundle_is_fresh():
    builder = runpy.run_path(str(ROOT / "scripts/build_claude_directory.py"))
    assert builder["stale_files"](builder["DESTINATION"], builder["bundle_files"]()) == []
