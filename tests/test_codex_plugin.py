import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "integrations" / "claude-code"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_codex_manifest_matches_the_claude_manifest_and_published_release() -> None:
    codex = _json(PLUGIN / ".codex-plugin" / "plugin.json")
    claude = _json(PLUGIN / ".claude-plugin" / "plugin.json")
    published = (ROOT / "PUBLISHED_VERSION").read_text(encoding="utf-8").strip()
    # The Claude directory listing and `/agent-bom:` commands keep the brand; the
    # Codex local-MCP variant is named apart from the public skills-only package.
    assert claude["name"] == "agent-bom"
    assert codex["name"] == "agent-bom-local"
    assert codex["interface"]["displayName"] != claude["displayName"]
    assert codex["version"] == claude["version"] == published
    assert codex["license"] == claude["license"]


def test_codex_manifest_paths_resolve_inside_the_plugin() -> None:
    codex = _json(PLUGIN / ".codex-plugin" / "plugin.json")
    interface = codex["interface"]
    for relative in (codex["skills"], codex["mcpServers"], interface["composerIcon"], interface["logo"]):
        assert relative.startswith("./")
        target = (PLUGIN / relative).resolve()
        assert target.is_relative_to(PLUGIN.resolve())
        assert target.exists(), relative
    assert len(interface["displayName"]) <= 30
    assert len(interface["shortDescription"]) <= 30
    assert all(len(prompt) <= 128 for prompt in interface["defaultPrompt"])


def test_codex_skills_are_the_shared_plugin_skills() -> None:
    skills = sorted(path.parent.name for path in (PLUGIN / "skills").glob("*/SKILL.md"))
    assert skills == ["activity", "affected", "audit-mcp", "audit-skills", "bom", "check", "checkup", "fix", "inventory", "scan"]
    for skill in skills:
        text = (PLUGIN / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
        # Codex has no `/plugin:skill` commands, so cross-references name the skill.
        assert not re.search(r"(?<!Claude Code: )`/agent-bom:", text), skill


def test_repo_marketplace_installs_the_plugin_from_this_repository() -> None:
    marketplace = _json(ROOT / ".agents" / "plugins" / "marketplace.json")
    [entry] = marketplace["plugins"]
    assert entry["name"] == "agent-bom-local"
    assert entry["source"] == {"source": "local", "path": "./integrations/claude-code"}
    assert entry["policy"] == {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}
    assert entry["category"]
    manifest = _json(ROOT / entry["source"]["path"] / ".codex-plugin" / "plugin.json")
    assert manifest["name"] == entry["name"]


def test_codex_packages_have_distinct_plugin_and_skill_names() -> None:
    # Codex namespaces a plugin's skills under its manifest name, so two packages
    # with one name would shadow each other's skills when both are installed.
    public = ROOT / "integrations" / "codex"
    names = {
        "local": _json(PLUGIN / ".codex-plugin" / "plugin.json")["name"],
        "public": _json(public / ".codex-plugin" / "plugin.json")["name"],
        "public-root": _json(public / "plugin.json")["name"],
    }
    assert names == {"local": "agent-bom-local", "public": "agent-bom", "public-root": "agent-bom"}
    local_skills = {f"{names['local']}:{p.parent.name}" for p in (PLUGIN / "skills").glob("*/SKILL.md")}
    public_skills = {f"{names['public']}:{p.parent.name}" for p in (public / "skills").glob("*/SKILL.md")}
    assert local_skills and public_skills and not local_skills & public_skills


def test_codex_and_claude_share_one_pinned_mcp_launcher() -> None:
    servers = _json(PLUGIN / ".mcp.json")["mcpServers"]
    published = (ROOT / "PUBLISHED_VERSION").read_text(encoding="utf-8").strip()
    assert set(servers) == {"agent-bom", "agent-bom-audit"}
    for server in servers.values():
        assert server["command"] == "uvx"
        assert server["args"][:2] == ["--from", f"agent-bom=={published}"]


def test_skill_command_pins_are_version_managed() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("cva", ROOT / "scripts" / "check_version_alignment.py")
    cva = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(cva)
    stale = "uvx --from agent-bom==0.90.0 agent-bom scan\nuvx --from 'agent-bom[aws]==0.90.0' agent-bom cloud aws\n"
    assert len(cva.scan_text("integrations/claude-code/skills/bom/SKILL.md", stale, "0.110.0")) == 2
