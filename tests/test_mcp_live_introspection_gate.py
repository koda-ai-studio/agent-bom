"""tool_risk_assessment is passive unless live mode is asked for and allowed."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "integrations" / "claude-code"


def _agents():
    remote = MCPServer(name="remote", url="https://notes.example.invalid/mcp", transport=TransportType.STREAMABLE_HTTP)
    local = MCPServer(name="local", command="must-not-run")
    return [Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="fixture.json", mcp_servers=[remote, local])]


@pytest.fixture
def no_network(monkeypatch):
    attempts: list[str] = []

    def _refuse(*args, **kwargs):
        attempts.append(repr(args[:1]))
        raise OSError("network disabled in test")

    monkeypatch.setattr(socket, "getaddrinfo", _refuse)
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    return attempts


def _call(monkeypatch, **kwargs):
    import agent_bom.discovery as discovery
    import agent_bom.mcp_introspect as introspect
    from agent_bom.mcp_tools.runtime import tool_risk_assessment_impl

    calls: list[dict] = []
    monkeypatch.setattr(discovery, "discover_all", lambda **_: _agents())
    monkeypatch.setattr(introspect, "introspect_servers_sync", lambda *a, **k: calls.append(k) or introspect.IntrospectionReport())
    data = json.loads(tool_risk_assessment_impl(_safe_path=lambda x: x, _truncate_response=lambda x: x, **kwargs))
    return data, calls


def test_call_without_live_makes_no_connection(monkeypatch, no_network):
    monkeypatch.delenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", raising=False)
    data, calls = _call(monkeypatch)
    assert calls == []
    assert no_network == []
    assert data["summary"]["live_requested"] is False
    assert data["audit"]["coverage"][0]["tools"]["status"] == "configuration_only"


def test_registered_tool_defaults_to_passive():
    from agent_bom.mcp_server import create_mcp_server

    tools = asyncio.run(create_mcp_server(profile="audit").list_tools())
    schema = next(tool.input_schema for tool in tools if tool.name == "tool_risk_assessment")
    assert schema["properties"]["live"]["default"] is False
    assert schema["properties"]["allow_command_execution"]["default"] is False


def test_server_setting_refuses_live_and_command_execution(monkeypatch, no_network):
    monkeypatch.setenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", "0")
    data, calls = _call(monkeypatch, live=True, allow_command_execution=True)
    assert calls == []
    assert no_network == []
    assert data["summary"]["live_requested"] is False
    assert data["summary"]["command_execution_allowed"] is False
    assert any("AGENT_BOM_MCP_LIVE_INTROSPECTION" in warning for warning in data["warnings"])


def test_live_still_works_when_server_allows_it(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", raising=False)
    data, calls = _call(monkeypatch, live=True)
    assert calls and calls[0]["allow_stdio"] is False
    assert data["summary"]["live_requested"] is True


def _plugin_servers() -> dict[str, dict]:
    claude = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    codex = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))["mcpServers"]
    return {**{f"claude:{k}": v for k, v in claude.items()}, **{f"codex:{k}": v for k, v in codex.items()}}


@pytest.mark.parametrize("name", sorted(_plugin_servers()))
def test_plugin_servers_launch_with_live_introspection_off(name):
    server = _plugin_servers()[name]
    assert server.get("env", {}).get("AGENT_BOM_MCP_LIVE_INTROSPECTION") == "0"
