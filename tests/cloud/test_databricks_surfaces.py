"""Databricks model-serving endpoints and cluster libraries are AI inventory, never unauthenticated MCP servers."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.cloud.databricks import _serving_endpoint_agent
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture


def _endpoint(name: str):
    return SimpleNamespace(name=name, state=SimpleNamespace(ready=SimpleNamespace(value="READY")), config=None, tags=None)


def test_serving_endpoints_are_inventory_not_mcp_surfaces() -> None:
    agent = _serving_endpoint_agent(_endpoint("databricks-meta-llama-3-3-70b-instruct"), "https://dbc-example.cloud.databricks.com")
    assert agent is not None
    (server,) = agent.mcp_servers
    assert not server.is_mcp_surface
    assert evaluate_mcp_auth_posture([agent]) == []
