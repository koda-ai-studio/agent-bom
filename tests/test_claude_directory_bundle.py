"""The directory ships only Claude runtime inputs, without changing local Codex."""

import json
import runpy
from pathlib import Path

import yaml

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
    for name in expected - {"README.md", "skills/bom/SKILL.md", ".claude-plugin/plugin.json"}:
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


def test_directory_bom_uses_only_declared_mcp_and_stops_on_incomplete_output():
    bundle = ROOT / "integrations/claude-directory"
    for path in (bundle / "skills").glob("*/SKILL.md"):
        metadata = yaml.safe_load(path.read_text().split("---", 2)[1])
        grants = [tool.strip() for tool in metadata["allowed-tools"].split(",")]
        assert all(tool == "Read" or tool.startswith("mcp__plugin_agent-bom_") for tool in grants)
    text = (bundle / "skills/bom/SKILL.md").read_text()
    metadata = yaml.safe_load(text.split("---", 2)[1])
    assert metadata["allowed-tools"] == "mcp__plugin_agent-bom_agent-bom__generate_sbom"
    assert metadata["capabilities"]["shell_exec"] is False
    assert "_truncated" in text
    assert "Never save or present a partial response as a complete BOM" in text
    assert "Do not fall back to shell commands" in text
    assert "config_path" in text and "cyclonedx" in text and "spdx" in text
    assert "uvx --from" not in text
    # Repository and Codex editions retain their explicitly supported CLI workflow.
    assert "Bash(uvx" in (ROOT / "integrations/claude-code/skills/bom/SKILL.md").read_text()
    assert "cloud aws" in (ROOT / "integrations/codex/skills/bom/SKILL.md").read_text()


def test_directory_disclosures_match_mcp_only_export():
    bundle = ROOT / "integrations/claude-directory"
    readme = (bundle / "README.md").read_text()
    assert "BOM output is returned in the conversation" in readme
    assert "no cloud-account BOM or shell fallback" in readme
    assert "30 minutes" in readme and "~/.agent-bom" in readme
    assert "uvx --from" not in readme
    manifest = json.loads((bundle / ".claude-plugin/plugin.json").read_text())
    assert manifest["documentationUrl"].endswith("/integrations/claude-directory/README.md")
