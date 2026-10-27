"""KSPM tools require a caller opt-in and respect the server's live-read gate."""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.mcp_tools import kspm


@pytest.mark.parametrize("tool", ["kspm_cluster_posture_impl", "kspm_workload_inventory_impl"])
@pytest.mark.parametrize("setting", [None, "0", "1"])
def test_kspm_default_never_contacts_cluster(monkeypatch, tool, setting) -> None:
    if setting is None:
        monkeypatch.delenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", setting)
    calls = []
    monkeypatch.setattr(kspm, "_collect_posture", lambda **kw: calls.append(kw))
    monkeypatch.setattr(kspm, "_collect_inventory", lambda **kw: calls.append(kw))
    data = json.loads(asyncio.run(getattr(kspm, tool)(_truncate_response=lambda s: s)))
    assert calls == []
    assert data["status"] == "not_collected"
    assert "live=true" in data["error"]


@pytest.mark.parametrize("tool", ["kspm_cluster_posture_impl", "kspm_workload_inventory_impl"])
@pytest.mark.parametrize("setting", ["0", "false", "invalid"])
def test_kspm_server_can_refuse_explicit_live_request(monkeypatch, tool, setting) -> None:
    monkeypatch.setenv("AGENT_BOM_MCP_LIVE_INTROSPECTION", setting)
    calls = []
    monkeypatch.setattr(kspm, "_collect_posture", lambda **kw: calls.append(kw))
    monkeypatch.setattr(kspm, "_collect_inventory", lambda **kw: calls.append(kw))
    data = json.loads(asyncio.run(getattr(kspm, tool)(live=True, _truncate_response=lambda s: s)))
    assert calls == []
    assert data["status"] == "not_collected"
    assert "AGENT_BOM_MCP_LIVE_INTROSPECTION" in data["error"]


def test_registered_kspm_tools_require_explicit_live_opt_in() -> None:
    from agent_bom.mcp_server import create_mcp_server

    tools = asyncio.run(create_mcp_server(profile="full").list_tools())
    selected = [t for t in tools if t.name in {"kspm_cluster_posture", "kspm_workload_inventory"}]
    assert len(selected) == 2
    for tool in selected:
        assert tool.input_schema["properties"]["live"]["type"] == "boolean"
        assert tool.input_schema["properties"]["live"]["default"] is False
