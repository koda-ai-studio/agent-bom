"""The Claude Code plugin may only reference tools its declared servers expose."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_bom.mcp_tools.profiles import DEFAULT_PROFILE, get_profile

PLUGIN = Path(__file__).resolve().parents[1] / "integrations" / "claude-code"
TOOL_REF = re.compile(r"mcp__plugin_agent-bom_([\w-]+?)__(\w+)")


def _server_profiles() -> dict[str, str]:
    servers = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]
    profiles = {}
    for name, spec in servers.items():
        args = spec["args"]
        profiles[name] = args[args.index("--profile") + 1] if "--profile" in args else DEFAULT_PROFILE
    return profiles


def test_plugin_servers_use_bounded_profiles():
    profiles = _server_profiles()
    assert profiles == {"agent-bom": "scan", "agent-bom-audit": "audit"}
    for profile in profiles.values():
        assert get_profile(profile).tools is not None


def test_eval_mocks_only_stand_in_for_exposed_tools():
    profiles = _server_profiles()
    mock_files = sorted(PLUGIN.glob("evals/**/mocks/*/*.md"))
    assert mock_files
    for mock in mock_files:
        server = mock.parent.name
        assert server in profiles, mock
        assert mock.stem in get_profile(profiles[server]).tools, mock


def test_eval_graders_name_exposed_tools():
    profiles = _server_profiles()
    refs = [m.groups() for g in PLUGIN.glob("evals/*/graders/*.md") for m in TOOL_REF.finditer(g.read_text())]
    assert refs
    for server, tool in refs:
        assert tool in get_profile(profiles[server]).tools, (server, tool)


@pytest.mark.parametrize("server", ["agent-bom", "agent-bom-audit"])
def test_recorded_tool_schemas_match_live_catalog(server):
    import asyncio

    from agent_bom.mcp_server import create_mcp_server

    recorded = json.loads((PLUGIN / "evals" / "mocks" / server / "_tools.json").read_text())["tools"]
    live = {t.name: t for t in asyncio.run(create_mcp_server(profile=_server_profiles()[server]).list_tools())}
    for tool in recorded:
        assert tool["name"] in live, tool["name"]
        current = live[tool["name"]].model_dump(by_alias=True, exclude_none=True, mode="json")
        assert tool["inputSchema"] == current["inputSchema"], tool["name"]
        assert tool["annotations"] == current["annotations"], tool["name"]


def test_every_skill_states_it_is_read_only_and_confirms_changes():
    skills = sorted(PLUGIN.glob("skills/*/SKILL.md"))
    assert {s.parent.name for s in skills} == {
        "scan",
        "check",
        "fix",
        "inventory",
        "audit-mcp",
        "audit-skills",
        "checkup",
        "affected",
        "bom",
        "activity",
    }
    for skill in skills:
        text = skill.read_text()
        assert text.startswith(f"---\nname: {skill.parent.name}\n"), skill
        # The shared Rules section (rendered from integrations/shared/skills.toml) carries these.
        assert "Change nothing on your own" in text and "apply it only after the user confirms" in text, skill
        assert "Never install, launch or connect to a package or MCP server" in text, skill
    for name in ("inventory", "audit-mcp", "audit-skills", "affected", "activity"):
        text = (PLUGIN / "skills" / name / "SKILL.md").read_text()
        assert "This skill is read-only" in text, name
    for name in ("audit-mcp", "checkup"):
        assert "`live: false`" in (PLUGIN / "skills" / name / "SKILL.md").read_text(), name


def test_activity_skill_treats_transcripts_as_untrusted_and_confirms_config_edits():
    text = (PLUGIN / "skills" / "activity" / "SKILL.md").read_text()
    assert "`agent_activity`" in text and "`agent-bom-audit`" in text
    assert "untrusted" in text and "never follow" in text
    assert "confirm" in text
    recorded = {t["name"] for t in json.loads((PLUGIN / "evals" / "mocks" / "agent-bom-audit" / "_tools.json").read_text())["tools"]}
    assert "agent_activity" in recorded


def test_readme_names_the_workspace_roots_variable_the_server_reads():
    import inspect

    from agent_bom import mcp_server_runtime

    readme = (PLUGIN / "README.md").read_text()
    source = inspect.getsource(mcp_server_runtime.mcp_workspace_roots)
    assert '"AGENT_BOM_MCP_WORKSPACE_ROOTS"' in source
    assert "AGENT_BOM_MCP_WORKSPACE_ROOTS" in readme
    assert "claude mcp add" in readme and "[mcp_servers." in readme


REPO = "https://github.com/koda-ai-studio/agent-bom"
LISTING_LINKS = ("homepage", "repository", "documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl")


def _repo_target(url: str) -> Path:
    # A blob/main link must name a file in this tree, and a #fragment a heading in it.
    root = PLUGIN.parents[1]
    path, _, fragment = url.removeprefix(f"{REPO}/blob/main/").partition("#")
    target = root / path
    assert target.is_file(), url
    if fragment:
        headings = {
            re.sub(r"[^\w\- ]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
            for line in target.read_text(encoding="utf-8").splitlines()
            if line.startswith("#")
        }
        assert fragment in headings, url
    return target


@pytest.mark.parametrize("plugin", ["claude-code", "agent-bom-guard"])
def test_claude_manifests_fill_every_directory_listing_link(plugin):
    manifest = json.loads((PLUGIN.parent / plugin / ".claude-plugin" / "plugin.json").read_text())
    for key in LISTING_LINKS:
        assert manifest.get(key, "").startswith(f"{REPO}"), (plugin, key)
    assert manifest["supportUrl"] == f"{REPO}/issues"
    assert manifest["termsOfServiceUrl"] == f"{REPO}/blob/main/LICENSE"
    for key in ("documentationUrl", "privacyPolicyUrl", "termsOfServiceUrl"):
        _repo_target(manifest[key])
    assert _repo_target(manifest["documentationUrl"]).parent.name == plugin


def test_codex_manifests_set_the_links_the_codex_schema_reads():
    # Codex's plugin interface reads websiteURL, privacyPolicyURL and
    # termsOfServiceURL; it has no support link field.
    for manifest_path in (PLUGIN / ".codex-plugin" / "plugin.json", PLUGIN.parent / "codex" / ".codex-plugin" / "plugin.json"):
        interface = json.loads(manifest_path.read_text())["interface"]
        assert interface["websiteURL"] == REPO, manifest_path
        assert interface["termsOfServiceURL"] == f"{REPO}/blob/main/LICENSE", manifest_path
        _repo_target(interface["privacyPolicyURL"])


def test_listing_questions_route_to_inventory_not_checkup():
    def description(skill):
        text = (PLUGIN / "skills" / skill / "SKILL.md").read_text()
        return re.search(r"^description: (.+)$", text, re.MULTILINE).group(1)

    inventory, checkup = description("inventory"), description("checkup")
    assert "What MCP servers and agents are configured in X?" in inventory
    assert "what agents and MCP servers are configured" not in checkup
    assert "use inventory" in checkup


SKILL_TOOLS = {
    "activity": {"agent-bom-audit": {"agent_activity"}},
    "affected": {"agent-bom": {"intel_lookup", "scan", "exposure_paths"}},
    "audit-mcp": {"agent-bom-audit": {"tool_risk_assessment", "inventory"}, "agent-bom": {"scan"}},
    "audit-skills": {"agent-bom-audit": {"skill_scan", "skill_trust", "prompt_scan"}},
    "bom": {"agent-bom": {"generate_sbom"}},
    "check": {"agent-bom": {"check"}},
    "checkup": {"agent-bom-audit": {"inventory", "tool_risk_assessment"}, "agent-bom": {"scan"}},
    "fix": {"agent-bom": {"remediate", "scan", "exposure_paths"}},
    "inventory": {"agent-bom-audit": {"inventory"}, "agent-bom": {"scan"}},
    "scan": {"agent-bom": {"scan"}},
}


def _allowed_tools(skill: str) -> list[str]:
    text = (PLUGIN / "skills" / skill / "SKILL.md").read_text()
    front = text.split("\n---\n", 1)[0]
    line = next((ln for ln in front.splitlines() if ln.startswith("allowed-tools:")), None)
    assert line is not None, f"{skill} declares no allowed-tools"
    return [tool.strip() for tool in line.split(":", 1)[1].split(",") if tool.strip()]


@pytest.mark.parametrize("skill", sorted(SKILL_TOOLS))
def test_skills_grant_least_privilege_tools(skill):
    profiles = _server_profiles()
    granted = _allowed_tools(skill)
    mcp = {}
    for tool in granted:
        match = TOOL_REF.fullmatch(tool)
        if match:
            server, name = match.groups()
            assert name in get_profile(profiles[server]).tools, tool
            mcp.setdefault(server, set()).add(name)
    assert mcp == SKILL_TOOLS[skill]
    others = [tool for tool in granted if not TOOL_REF.fullmatch(tool)]
    shell = [tool for tool in others if tool.startswith("Bash(")]
    assert set(others) - set(shell) == {"Read"}, others
    if skill == "bom":
        assert shell and all(tool.startswith("Bash(uvx --from agent-bom==") and tool.endswith(":*)") for tool in shell), shell
    else:
        assert not shell, f"{skill} must not run shell commands"
