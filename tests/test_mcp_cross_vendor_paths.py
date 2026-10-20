"""MCP cross_vendor_paths answers with the exact REST read behind /v1/graph/attack-paths/cross-vendor."""

from __future__ import annotations

import asyncio
import json

from agent_bom.mcp_tools.cross_vendor_paths import cross_vendor_paths_impl
from tests.test_graph_cross_vendor_queue import _graph
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401

_COMPARED = ("attack_paths", "nodes", "edges", "pagination", "vendor_facets", "snapshot_generation", "scan_id", "count_metadata")


def _rest(client, headers, **params):
    response = client.get("/v1/graph/attack-paths/cross-vendor", params={"scan_id": "vendor-scan", **params}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_mcp_matches_rest_for_the_whole_slice_and_a_vendor_pair(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    for params in ({"limit": 25}, {"source_vendor": "snowflake", "target_vendor": "aws", "limit": 25}, {"limit": 1}):
        rest = _rest(client, headers["tenant-a"], **params)
        mcp = json.loads(asyncio.run(cross_vendor_paths_impl(tenant_id="tenant-a", scan_id="vendor-scan", **params)))
        assert mcp["tool"] == "cross_vendor_paths" and mcp["source"] == "v1_graph_attack_paths_cross_vendor"
        for key in _COMPARED:
            assert mcp[key] == rest[key], key
    assert mcp["vendor_facets"]["unit"] == "paths"


def test_mcp_rejects_bad_vendor_ids_like_rest(api, monkeypatch):  # noqa: F811
    _client, store, _headers = api
    store.save_graph(_graph("tenant-a"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    body = json.loads(asyncio.run(cross_vendor_paths_impl(tenant_id="tenant-a", scan_id="vendor-scan", source_vendor="AWS; DROP")))
    assert "error" in body


def test_mcp_never_reads_another_tenant(api, monkeypatch):  # noqa: F811
    _client, store, _headers = api
    store.save_graph(_graph("tenant-a"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-b")
    text = asyncio.run(cross_vendor_paths_impl(tenant_id="tenant-b", scan_id="vendor-scan"))
    assert "snowflake:table:T" not in text


def test_tool_is_catalogued_read_only_with_vendor_inputs():
    from agent_bom.mcp_server import build_server_card

    tool = next(tool for tool in build_server_card()["tools"] if tool["name"] == "cross_vendor_paths")
    assert tool["annotations"]["readOnlyHint"] is True
    assert "READ" in tool["capability_classes"]
    from agent_bom.mcp_server import create_mcp_server

    listed = {item.name: item for item in asyncio.run(create_mcp_server(profile="graph").list_tools())}
    assert listed["cross_vendor_paths"].annotations.read_only_hint is True
    assert {"source_vendor", "target_vendor", "offset", "limit", "snapshot_generation"} <= set(
        listed["cross_vendor_paths"].input_schema["properties"]
    )
