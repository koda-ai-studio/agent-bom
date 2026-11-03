"""User-level Windsurf (Cascade) MCP configs documented on 2026-11-02.

The Windsurf docs now redirect to the renamed product's docs:
https://docs.devin.ai/windsurf/plugins/cascade/mcp lists the Cascade config at
``~/.config/devin/mcp_config.json`` (macOS, Linux) or
``%AppData%/devin/mcp_config.json`` (Windows), and the editor's build-specific
files ``~/.codeium/windsurf/mcp_config.json`` (stable) and
``~/.codeium/windsurf-next/mcp_config.json`` (Next).
https://docs.devin.ai/desktop/devin-desktop-faq lists ``~/.codeium/mcp_config.json``
as the per-user MCP config.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.discovery import CONFIG_LOCATIONS, discover_global_configs
from agent_bom.models import AgentType

_DOCUMENTED = {
    "Darwin": [
        ".codeium/windsurf/mcp_config.json",
        ".codeium/windsurf-next/mcp_config.json",
        ".codeium/mcp_config.json",
        ".config/devin/mcp_config.json",
    ],
    "Linux": [
        ".codeium/windsurf/mcp_config.json",
        ".codeium/windsurf-next/mcp_config.json",
        ".codeium/mcp_config.json",
        ".config/devin/mcp_config.json",
    ],
    "Windows": [
        ".codeium/windsurf/mcp_config.json",
        ".codeium/windsurf-next/mcp_config.json",
        ".codeium/mcp_config.json",
        "AppData/Roaming/devin/mcp_config.json",
    ],
}
_CASES = [(platform, rel) for platform, rels in _DOCUMENTED.items() for rel in rels]


@pytest.mark.parametrize(("platform", "rel"), _CASES)
def test_documented_user_config_is_discovered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, rel: str) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: platform)
    config = tmp_path / rel
    config.parent.mkdir(parents=True)
    config.write_text('{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}')

    agents = discover_global_configs([AgentType.WINDSURF], quiet=True)

    assert [(agent.agent_type, Path(agent.config_path).resolve()) for agent in agents] == [(AgentType.WINDSURF, config.resolve())]
    assert [server.name for server in agents[0].mcp_servers] == ["github"]


@pytest.mark.parametrize("platform", sorted(_DOCUMENTED))
def test_documented_paths_are_listed_per_platform(platform: str) -> None:
    listed = CONFIG_LOCATIONS[AgentType.WINDSURF][platform]
    assert {f"~/{rel}" for rel in _DOCUMENTED[platform]} <= set(listed)
