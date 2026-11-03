"""MCP clients' documented user-level config files are discovered on every OS."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_bom.discovery as discovery
from agent_bom.discovery.platform_config import CONFIG_LOCATIONS
from agent_bom.models import AgentType

DOCUMENTED = [
    (AgentType.WINDSURF, ".codeium/windsurf/mcp_config.json"),
    (AgentType.AMAZON_Q, ".aws/amazonq/default.json"),
    (AgentType.AMAZON_Q, ".aws/amazonq/mcp.json"),
    (AgentType.CLINE, ".cline/data/settings/cline_mcp_settings.json"),
]


@pytest.mark.parametrize("os_name", ["Darwin", "Linux", "Windows"])
@pytest.mark.parametrize(("agent_type", "relative"), DOCUMENTED)
def test_documented_path_registered(agent_type: AgentType, relative: str, os_name: str) -> None:
    assert f"~/{relative}" in CONFIG_LOCATIONS[agent_type][os_name]


@pytest.mark.parametrize("os_name", ["Darwin", "Linux", "Windows"])
@pytest.mark.parametrize(("agent_type", "relative"), DOCUMENTED)
def test_documented_path_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent_type: AgentType, relative: str, os_name: str
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(discovery, "get_platform", lambda: os_name)
    config = tmp_path / relative
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "@example/docs-mcp@1.0.0"]}}}))

    agents = discovery.discover_global_configs([agent_type], quiet=True)

    servers = [(server.name, Path(server.config_path or "").resolve()) for agent in agents for server in agent.mcp_servers]
    assert ("docs", config.resolve()) in servers
