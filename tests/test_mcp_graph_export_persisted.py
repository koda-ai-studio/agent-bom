"""MCP ``graph_export`` exports the bound tenant's persisted graph; it never scans the server host in that mode."""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from tests.test_graph_tenant_scope_and_bounds import _path_graph

TENANT = "tenant-a"


def _no_host_scan(*_args, **_kwargs):
    raise AssertionError("graph_export scanned the MCP server host in persisted mode")


@pytest.fixture
def export(tmp_path, monkeypatch):
    from agent_bom import mcp_server

    store = SQLiteGraphStore(tmp_path / "graph.db")
    monkeypatch.setattr(stores, "_graph_store", store)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    scans: list[str] = []

    async def host_scan(*_args, **_kwargs):
        scans.append("host")
        return [], [], [], []

    def call(arguments: dict | None = None, *, scan=host_scan) -> tuple[dict | str, list[str]]:
        monkeypatch.setattr(mcp_server, "_run_scan_pipeline", scan)
        server = mcp_server.create_mcp_server(profile="full")
        result = asyncio.run(server.call_tool("graph_export", arguments or {}))
        text = result.content[0].text
        try:
            return json.loads(text), scans
        except ValueError:
            return text, scans

    return store, call


def test_tenant_bound_export_is_the_persisted_tenant_graph(export, monkeypatch):
    store, call = export
    store.save_graph(_path_graph(TENANT))
    store.save_graph(_path_graph("other-tenant"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)

    body, scans = call(scan=_no_host_scan)
    assert scans == []
    ids = {node["id"] for node in body["nodes"]}
    assert ids == {"principal:reader", "data:store"}, body
    assert {node["label"] for node in body["nodes"]} == {f"{TENANT}-reader", f"{TENANT}-store"}
    assert [(edge["source"], edge["target"]) for edge in body["edges"]] == [("principal:reader", "data:store")]
    assert body["source"] == "persisted_graph"
    assert body["scope"]["tenant_id"] == TENANT
    assert body["completeness"]["complete"] is True


@pytest.mark.parametrize("fmt", ["graphml", "cypher", "dot", "mermaid"])
def test_tenant_bound_text_formats_render_the_persisted_graph(export, monkeypatch, fmt):
    store, call = export
    store.save_graph(_path_graph(TENANT))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    body, scans = call({"format": fmt}, scan=_no_host_scan)
    assert scans == []
    assert isinstance(body, str) and "reader" in body and "provider:local" not in body


def test_tenant_bound_without_a_persisted_graph_refuses_instead_of_scanning_the_host(export, monkeypatch):
    _store, call = export
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    body, scans = call(scan=_no_host_scan)
    assert scans == []
    assert body["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE", body
    assert body["error"]["details"]["tenant_id"] == TENANT


def test_unbound_local_server_without_a_store_keeps_the_host_export(export, monkeypatch):
    _store, call = export
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    body, scans = call()
    assert scans == ["host"]
    assert "error" not in body, body
