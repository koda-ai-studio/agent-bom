"""MCP tools on Postgres serve the server-bound tenant's estate, and only that tenant's."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from uuid import uuid4

import pytest

from tests.test_graph_tenant_scope_and_bounds import _path_graph

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated live PostgreSQL")


@pytest.fixture
def bound_mcp(monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    suffix = uuid4().hex[:10]
    tenant_a, tenant_b = f"mcp-rls-a-{suffix}", f"mcp-rls-b-{suffix}"
    store = PostgresGraphStore()
    for tenant in (tenant_a, tenant_b):
        graph = _path_graph(tenant)
        graph.scan_id = f"{tenant}-scan"
        token = set_current_tenant(tenant)
        try:
            store.save_graph(graph)
        finally:
            reset_current_tenant(token)
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", tenant_a)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")

    def call(name: str, **arguments) -> tuple[str, dict]:
        result = asyncio.run(server.call_tool(name, arguments))
        text = result.content[0].text
        return text, json.loads(text)

    logging.getLogger("agent_bom").setLevel(logging.ERROR)
    return call, tenant_a, tenant_b


def test_bound_tenant_estate_is_visible(bound_mcp):
    call, tenant_a, _ = bound_mcp
    _, summary = call("inventory_summary")
    assert summary.get("total_assets", 0) > 0, summary
    _, paths = call("exposure_paths")
    assert paths["tenant_id"] == tenant_a
    assert paths["total"] == 1
    _, pinned = call("exposure_paths", scan_id=f"{tenant_a}-scan")
    assert "error" not in pinned, pinned
    assert pinned["scan_id"] == f"{tenant_a}-scan"


def test_other_tenant_rows_never_reach_the_bound_tenant(bound_mcp):
    call, _, tenant_b = bound_mcp
    _, pinned = call("exposure_paths", scan_id=f"{tenant_b}-scan")
    assert pinned["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    for name, arguments in (("inventory_summary", {}), ("inventory_list", {"limit": 50}), ("exposure_paths", {})):
        text, _ = call(name, **arguments)
        assert tenant_b not in text, name
