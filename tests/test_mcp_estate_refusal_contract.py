"""MCP graph, inventory and findings tools refuse a not-ready current estate with one typed, retryable error."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from agent_bom.api import current_graph
from tests.test_current_estate_seeding_refusal import TENANT, client, seeding  # noqa: F401 - pytest fixtures

TOOLS = [
    ("inventory_summary", {}),
    ("inventory_list", {"limit": 3}),
    ("context_graph", {}),
    ("cross_vendor_paths", {}),
    ("exposure_paths", {}),
    ("findings_query", {"limit": 2}),
]


@pytest.fixture
def server(client, monkeypatch):  # noqa: F811 - the imported fixture
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    from agent_bom.mcp_server import create_mcp_server

    mcp = create_mcp_server(profile="full")

    def call(name: str, arguments: dict) -> dict:
        result = asyncio.run(mcp.call_tool(name, arguments))
        return json.loads(result.content[0].text)

    return call


def _assert_typed_refusal(payload: dict, reason: str, retry_after: int) -> None:
    error = payload.get("error")
    assert isinstance(error, dict), payload
    assert error["code"] == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE", payload
    assert error["details"]["reason"] == reason, payload
    assert error["details"]["retry_after_seconds"] == retry_after, payload


@pytest.mark.parametrize(("name", "arguments"), TOOLS, ids=[name for name, _ in TOOLS])
def test_tool_refuses_typed_while_seeding_then_serves(server, seeding, caplog, name, arguments):  # noqa: F811
    with caplog.at_level(logging.WARNING):
        _assert_typed_refusal(server(name, arguments), "current_estate_seeding", 2)
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR], caplog.text
    assert "Traceback" not in caplog.text

    seeding._boot_seed_done.set()
    served = server(name, arguments)
    # The fixture estate has no agents, so context_graph then answers its own not-found.
    allowed = (None, "AGENTBOM_MCP_NOT_FOUND_RESOURCE") if name == "context_graph" else (None,)
    assert (served.get("error") or {}).get("code") in allowed, served


@pytest.mark.parametrize(("name", "arguments"), TOOLS[:5], ids=[name for name, _ in TOOLS[:5]])
def test_tool_refuses_typed_while_the_generation_rotates(server, monkeypatch, caplog, name, arguments):
    def rotating(_tenant_id=None):
        raise current_graph._generation_rotating()

    monkeypatch.setattr(current_graph, "_refuse_current_read_while_seeding", rotating)
    with caplog.at_level(logging.WARNING):
        _assert_typed_refusal(server(name, arguments), current_graph.ROTATING_CODE, 1)
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR], caplog.text
