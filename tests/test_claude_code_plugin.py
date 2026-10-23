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
        assert "read-only" in text or "Do not install" in text or "only edit" in text, skill
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
