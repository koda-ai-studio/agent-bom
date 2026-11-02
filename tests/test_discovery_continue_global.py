"""Discover user-level Continue YAML without executing configured servers."""

from pathlib import Path

import pytest

from agent_bom.discovery import discover_global_configs
from agent_bom.models import AgentType, TransportType


@pytest.fixture
def continue_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    config_dir = tmp_path / ".continue"
    config_dir.mkdir()
    return config_dir


@pytest.mark.parametrize("platform", ["Darwin", "Linux", "Windows"])
def test_global_continue_yaml_is_discovered(continue_home: Path, monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: platform)
    config = continue_home / "config.yaml"
    config.write_text(
        "name: Local\nversion: 1.0.0\nschema: v1\nmcpServers:\n"
        "  - name: sqlite\n    command: uvx\n    args: [mcp-server-sqlite]\n"
        "  - name: docs\n    type: streamable-http\n    url: https://mcp.example.com/mcp\n"
    )

    def deny_spawn(*args: object, **kwargs: object) -> None:
        pytest.fail("Configuration discovery must not execute a server")

    monkeypatch.setattr("subprocess.Popen", deny_spawn)
    agents = discover_global_configs([AgentType.CONTINUE], quiet=True)

    assert len(agents) == 1
    assert agents[0].config_path == str(config)
    assert agents[0].agent_type == AgentType.CONTINUE
    servers = {server.name: server for server in agents[0].mcp_servers}
    assert servers["sqlite"].command == "uvx"
    assert servers["sqlite"].args == ["mcp-server-sqlite"]
    assert servers["docs"].transport == TransportType.STREAMABLE_HTTP
    assert servers["docs"].url == "https://mcp.example.com/mcp"


@pytest.mark.parametrize("contents", ["mcpServers: [unterminated", "- not-a-config", "!!python/object:invalid {}"])
def test_invalid_yaml_does_not_hide_legacy_json(continue_home: Path, contents: str) -> None:
    (continue_home / "config.yaml").write_text(contents)
    legacy = continue_home / "config.json"
    legacy.write_text('{"mcpServers":{"legacy":{"command":"uvx","args":["mcp-server-sqlite"]}}}')

    agents = discover_global_configs([AgentType.CONTINUE], quiet=True)

    assert [agent.config_path for agent in agents] == [str(legacy)]
    assert agents[0].mcp_servers[0].name == "legacy"


def test_continue_yaml_symlink_outside_config_directory_is_skipped(continue_home: Path) -> None:
    target = continue_home.parent / "outside.yaml"
    target.write_text("mcpServers:\n  - name: outside\n    command: uvx\n    args: [mcp-server-sqlite]\n")
    (continue_home / "config.yaml").symlink_to(target)

    assert discover_global_configs([AgentType.CONTINUE], quiet=True) == []
