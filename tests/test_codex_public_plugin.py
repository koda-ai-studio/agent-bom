"""The skills-only Codex package for the public plugin directory.

It must stay in sync with the MCP plugin skills (same jobs, same safety rules),
cite only real CLI commands and flags, and build into a ZIP that the directory
accepts: no hooks, no app references, no MCP configuration.
"""

from __future__ import annotations

import importlib.util
import json
import re
import struct
import sys
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import click
import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
CODEX = ROOT / "integrations" / "codex"
CLAUDE = ROOT / "integrations" / "claude-code"
SPEC = ROOT / "integrations" / "shared" / "skills.toml"
PUBLISHED = (ROOT / "PUBLISHED_VERSION").read_text(encoding="utf-8").strip()
JOBS = ["activity", "affected", "audit-mcp", "audit-skills", "bom", "check", "checkup", "fix", "inventory", "scan"]
_PINNED_CMD = re.compile(r"`uvx --from '?agent-bom(?:\[[a-z]+\])?==(\d+\.\d+\.\d+)'? agent-bom ([^`]+)`")


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _spec() -> dict:
    return tomllib.loads(SPEC.read_text(encoding="utf-8"))


def _frontmatter(path: Path) -> dict:
    import yaml

    text = path.read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, path
    return yaml.safe_load(match.group(1))


def _skill_names(plugin: Path) -> list[str]:
    return sorted(path.parent.name for path in (plugin / "skills").glob("*/SKILL.md"))


def _manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_rendered_skills_match_the_shared_spec() -> None:
    render = _script("render_plugin_skills")
    assert render.main(["--check"]) == 0


def test_render_check_detects_a_hand_edited_skill() -> None:
    render = _script("render_plugin_skills")
    outputs = render.render_all()
    assert render.stale_paths(outputs) == []
    target = next(path for path in outputs if path.is_relative_to(CODEX / "skills"))

    def tampered(path: Path) -> str:
        return outputs[path].replace("untrusted data", "trusted data") if path == target else outputs[path]

    assert render.stale_paths(outputs, read=tampered) == [target]


def test_both_skill_sets_cover_the_same_jobs() -> None:
    assert _skill_names(CODEX) == _skill_names(CLAUDE) == sorted(_spec()["skills"]) == JOBS


def test_both_skill_sets_carry_every_shared_safety_rule() -> None:
    rules = _spec()["rules"]
    assert set(rules) >= {"untrusted", "secrets", "exact", "no_launch", "confirm"}
    for plugin in (CODEX, CLAUDE):
        for job in JOBS:
            text = (plugin / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
            section = text.split("\n## Rules\n", 1)
            assert len(section) == 2, f"{plugin.name}/{job} has no Rules section"
            for rule in rules.values():
                assert f"- {rule}" in section[1], f"{plugin.name}/{job} is missing: {rule[:40]}"


def test_descriptions_and_capabilities_match_the_mcp_skills() -> None:
    spec = _spec()["skills"]
    for job in JOBS:
        claude = _frontmatter(CLAUDE / "skills" / job / "SKILL.md")
        codex = _frontmatter(CODEX / "skills" / job / "SKILL.md")
        assert claude["description"] == codex["description"] == spec[job]["description"], job
        assert codex["name"] == claude["name"] == job
        shared = {k: v for k, v in claude["capabilities"].items() if k not in {"shell_exec", "outbound_http"}}
        assert {k: v for k, v in codex["capabilities"].items() if k in shared} == shared, job


def test_codex_skills_declare_provenance_and_shell_execution() -> None:
    for job in JOBS:
        meta = _frontmatter(CODEX / "skills" / job / "SKILL.md")
        assert meta["homepage"] == "https://github.com/koda-ai-studio/agent-bom"
        assert meta["source"] == f"https://github.com/koda-ai-studio/agent-bom/tree/main/integrations/codex/skills/{job}"
        assert meta["license"] == "Apache-2.0"
        caps = meta["capabilities"]
        # uv fetches the pinned release from PyPI, so every shell skill can reach the network.
        assert caps["shell_exec"] is True and caps["outbound_http"] is True
        assert caps["write_findings"] is False
        assert meta["requires"] == {"bins": ["uvx"]}


def test_codex_skills_drive_the_cli_not_mcp_tools() -> None:
    for job in JOBS:
        text = (CODEX / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
        assert "agent-bom-audit" not in text and "MCP tool" not in text, job
        assert not re.search(r"\bCall `", text), job
        assert _PINNED_CMD.search(text), job
        assert "Claude Code:" not in text and "/agent-bom:" not in text, job


def _cli_tree() -> click.Group:
    from agent_bom.cli import main as cli_main

    return cli_main


def _resolve(tokens: list[str]) -> tuple[click.Command, list[str]]:
    command: click.Command = _cli_tree()
    params = [opt for param in command.params for opt in getattr(param, "opts", [])]
    rest = list(tokens)
    while rest and isinstance(command, click.Group) and rest[0] in command.commands:
        command = command.commands[rest.pop(0)]
        params += [opt for param in command.params for opt in getattr(param, "opts", [])]
    return command, params + ["-h", "--help"]


def test_every_cited_command_and_flag_exists_in_the_cli() -> None:
    cited = 0
    for job in JOBS:
        text = (CODEX / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
        for version, command in _PINNED_CMD.findall(text):
            assert version == PUBLISHED, (job, command)
            tokens = [tok for tok in command.split() if tok != "--agent-mode"]
            leaf, options = _resolve(tokens)
            assert leaf is not _cli_tree(), (job, command)
            for flag in re.findall(r"(?<![\w-])(--?[a-z][a-z-]*)", command):
                if flag == "--agent-mode":
                    continue
                assert flag in options, f"{job}: {flag} is not an option of `{command}`"
            cited += 1
    assert cited >= 15


def test_every_flag_fragment_belongs_to_a_command_the_skill_runs() -> None:
    checked = 0
    for job in JOBS:
        text = (CODEX / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
        body = text.split("\n## Running agent-bom\n", 1)[0]
        options: set[str] = set()
        for _version, command in _PINNED_CMD.findall(body):
            options.update(_resolve([tok for tok in command.split() if tok != "--agent-mode"])[1])
        fragments = [span for span in re.findall(r"`([^`]+)`", body) if span.startswith("-")]
        for fragment in fragments:
            for flag in re.findall(r"(?<![\w-])(--?[a-z][a-z-]*)", fragment):
                assert flag in options, f"{job}: `{fragment}` cites {flag}, which none of its commands accept"
            checked += 1
    assert checked >= 20


def test_codex_skills_never_cite_write_or_launch_flags_as_commands() -> None:
    for job in JOBS:
        text = (CODEX / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
        for _version, command in _PINNED_CMD.findall(text):
            for forbidden in ("--apply", "--open-pr", "--live", "--allow-command-execution", "--push-url", "--check-packages"):
                assert forbidden not in command.split(), (job, command)


def test_codex_skill_pins_are_version_managed() -> None:
    cva = _script("check_version_alignment")
    stale = (
        "`uvx --from agent-bom==0.90.0 agent-bom --agent-mode scan -q`\n"
        "`uvx --from 'agent-bom[aws]==0.90.0' agent-bom cloud aws --profile <profile>`\n"
    )
    drift = cva.scan_text("integrations/codex/skills/scan/SKILL.md", stale, "0.111.0", published=PUBLISHED)
    assert len(drift) == 2
    for job in JOBS:
        rel = f"integrations/codex/skills/{job}/SKILL.md"
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert cva.scan_text(rel, text, "0.111.0", published=PUBLISHED) == [], job
    manifest = (CODEX / "plugin.json").read_text(encoding="utf-8")
    assert cva.scan_text("integrations/codex/plugin.json", manifest.replace(PUBLISHED, "0.90.0"), "0.111.0", published=PUBLISHED)


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def test_manifests_meet_the_directory_listing_limits() -> None:
    root = _manifest(CODEX / "plugin.json")
    overlay = _manifest(CODEX / ".codex-plugin" / "plugin.json")
    interface = root["extensions"]["com.openai"]["interface"]
    assert overlay["interface"] == interface
    for manifest in (root, overlay):
        assert manifest["name"] == "agent-bom" and manifest["version"] == PUBLISHED
        assert manifest["author"]["name"] and manifest["description"]
        assert not {"mcpServers", "apps", "hooks"} & set(manifest)
    assert not {"apps", "hooks"} & set(root["extensions"]["com.openai"])
    assert len(interface["displayName"]) <= 30
    assert len(interface["shortDescription"]) <= 30
    assert len(interface["longDescription"]) <= 4000
    assert 1 <= len(interface["defaultPrompt"]) <= 3
    assert all(len(prompt) <= 128 for prompt in interface["defaultPrompt"])
    assert len(interface["developerName"]) <= 80 and interface["category"]
    assert len(interface["capabilities"]) <= 20
    for key in ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"):
        assert interface[key].startswith("https://") and len(interface[key]) <= 1024, key
        assert "@" not in interface[key], key
    assert re.fullmatch(r"#[0-9A-F]{6}", interface["brandColor"], re.IGNORECASE)
    for key in ("logo", "composerIcon"):
        relative = interface[key]
        assert relative.startswith("./assets/")
        width, height = _png_size(CODEX / relative)
        assert width == height >= 48
        assert (CODEX / relative).stat().st_size <= 5 * 1024 * 1024
    assert "MCP server" not in interface["shortDescription"]


def test_listing_icon_is_rendered_by_the_brand_asset_script() -> None:
    script = (ROOT / "ui" / "scripts" / "render-brand-assets.mjs").read_text(encoding="utf-8")
    match = re.search(r"for \(const plugin of \[([^\]]+)\]\)", script)
    assert match and "'codex'" in match.group(1)
    assert (CODEX / "assets" / "icon.png").read_bytes() == (CLAUDE / "assets" / "icon.png").read_bytes()


@pytest.fixture(scope="module")
def built_zip(tmp_path_factory: pytest.TempPathFactory) -> Path:
    builder = _script("build_codex_plugin_zip")
    out = tmp_path_factory.mktemp("zip") / "agent-bom-codex-plugin.zip"
    assert builder.main(["--output", str(out)]) == 0
    return out


def test_zip_holds_only_the_allowed_files(built_zip: Path) -> None:
    with zipfile.ZipFile(built_zip) as archive:
        names = sorted(archive.namelist())
        expected = sorted(
            [".codex-plugin/plugin.json", "LICENSE", "README.md", "assets/icon.png", "plugin.json"]
            + [f"skills/{job}/SKILL.md" for job in JOBS]
        )
        assert names == expected
        assert not any(re.search(r"(^|/)(hooks|\.app\.json|\.?mcp\.json)", name) for name in names)
        for name in names:
            info = archive.getinfo(name)
            assert not name.startswith("/") and ".." not in name.split("/")
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
        root = json.loads(archive.read("plugin.json"))
        assert root["version"] == PUBLISHED
        assert archive.read("skills/scan/SKILL.md") == (CODEX / "skills" / "scan" / "SKILL.md").read_bytes()


def test_zip_build_is_reproducible(built_zip: Path, tmp_path: Path) -> None:
    builder = _script("build_codex_plugin_zip")
    again = tmp_path / "again.zip"
    assert builder.main(["--output", str(again)]) == 0
    assert again.read_bytes() == built_zip.read_bytes()


def test_zip_builder_rejects_a_forbidden_file(tmp_path: Path) -> None:
    builder = _script("build_codex_plugin_zip")
    with pytest.raises(builder.PackageError, match="not allowed"):
        builder.validate_names(["plugin.json", "hooks/hooks.json"])
    with pytest.raises(builder.PackageError, match="not allowed"):
        builder.validate_names(["plugin.json", ".mcp.json"])
    with pytest.raises(builder.PackageError, match="shortDescription"):
        manifest = _manifest(CODEX / "plugin.json")
        manifest["extensions"]["com.openai"]["interface"]["shortDescription"] = "x" * 31
        builder.validate_manifest(manifest)
    with pytest.raises(builder.PackageError, match="mcpServers"):
        builder.validate_manifest({**_manifest(CODEX / "plugin.json"), "mcpServers": "./.mcp.json"})


def test_readme_lists_every_command_and_destination() -> None:
    readme = (CODEX / "README.md").read_text(encoding="utf-8")
    assert "## Privacy" in readme and "## What it runs, reads and sends" in readme
    commands: set[str] = set()
    for job in JOBS:
        text = (CODEX / "skills" / job / "SKILL.md").read_text(encoding="utf-8")
        for _version, command in _PINNED_CMD.findall(text):
            words = [tok for tok in command.split() if not tok.startswith("-")]
            commands.add(" ".join(words[:2]) if words[0] in {"mcp", "skills", "cloud"} else words[0])
    for command in commands:
        assert f"`{command}`" in readme, command
    for host in ("pypi.org", "api.osv.dev", "api.github.com", "registry.npmjs.org"):
        assert host in readme, host


def test_agent_bom_skill_audit_reports_no_findings_on_the_codex_package(tmp_path: Path) -> None:
    from agent_bom.cli import main as cli_main

    out = tmp_path / "skills.json"
    result = CliRunner().invoke(
        cli_main,
        ["skills", "scan", str(CODEX), "-f", "json", "-o", str(out), "--catalog", str(tmp_path / "catalog.json")],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["files_scanned"] >= len(JOBS)
    findings = [(f["path"], x["title"]) for f in report["files"] for x in f["audit"]["findings"]]
    assert findings == []
    assert report["summary"]["findings"] == 0


def test_codex_package_links_resolve_outside_the_repository() -> None:
    # The directory ZIP holds only integrations/codex, so a relative link leaves it.
    root = ROOT / "integrations" / "codex"
    for path in [root / "README.md", *sorted((root / "skills").glob("*/SKILL.md"))]:
        relative = [m for m in re.findall(r"\]\(([^)]+)\)", path.read_text()) if not m.startswith(("https://", "#"))]
        assert relative == [], (path.name, relative)


def test_audit_skills_reads_finding_fields_that_exist() -> None:
    # possibly_documentation is a value of a finding's `context`, not a field of its own.
    root = ROOT / "integrations"
    for skill in (root / "codex" / "skills" / "audit-skills" / "SKILL.md", root / "claude-code" / "skills" / "audit-skills" / "SKILL.md"):
        text = skill.read_text()
        assert "`possibly_documentation`)" not in text and "marked `possibly_documentation`" not in text
        assert "`context` is `possibly_documentation`" in text
