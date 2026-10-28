"""MCP ``graph_export`` pages a persisted graph with a generation-pinned cursor and truthful completeness."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.test_mcp_graph_export_persisted import TENANT, _no_host_scan, export  # noqa: F401 - fixture

NODES = 23


def _chain(scan_id: str = "scan-1") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=TENANT)
    for index in range(NODES):
        graph.add_node(UnifiedNode(id=f"pkg:{index:03d}", entity_type=EntityType.PACKAGE, label=f"pkg-{index:03d}"))
    for index in range(NODES - 1):
        graph.add_edge(UnifiedEdge(source=f"pkg:{index:03d}", target=f"pkg:{index + 1:03d}", relationship=RelationshipType.DEPENDS_ON))
    return graph


@pytest.fixture
def paged(export, monkeypatch):  # noqa: F811 - fixture
    store, call = export
    store.save_graph(_chain())
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    return store, call


def _owned(body: dict) -> set[str]:
    return {node["id"] for node in body["nodes"] if not (node.get("attributes") or {}).get("page_reference")}


def test_pages_cover_every_node_and_edge_exactly_once_with_truthful_completeness(paged):
    _store, call = paged
    seen_nodes: list[str] = []
    seen_edges: list[tuple[str, str]] = []
    cursor = None
    pages = 0
    while True:
        body, scans = call({"limit": 10, **({"cursor": cursor} if cursor else {})}, scan=_no_host_scan)
        assert scans == []
        pages += 1
        owned = _owned(body)
        seen_nodes.extend(owned)
        seen_edges.extend((edge["source"], edge["target"]) for edge in body["edges"])
        assert all(edge["source"] in owned for edge in body["edges"])
        completeness, pagination = body["completeness"], body["pagination"]
        assert completeness["returned"] == len(owned) and completeness["total"] == NODES
        cursor = pagination["next_cursor"]
        if cursor is None:
            assert completeness["complete"] is True and pagination["has_more"] is False
            break
        assert completeness["complete"] is False and completeness["truncated"] is True
        assert pagination["has_more"] is True
    assert pages == 3
    assert sorted(seen_nodes) == [f"pkg:{index:03d}" for index in range(NODES)]
    assert len(seen_edges) == len(set(seen_edges)) == NODES - 1


def test_malformed_cursor_is_invalid_argument(paged):
    _store, call = paged
    body, _ = call({"cursor": "not-a-cursor"}, scan=_no_host_scan)
    assert body["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"
    assert body["error"]["details"]["argument"] == "cursor"


def test_cursor_from_a_replaced_snapshot_is_a_stale_conflict(paged):
    store, call = paged
    first, _ = call({"limit": 10}, scan=_no_host_scan)
    cursor = first["pagination"]["next_cursor"]
    store.save_graph(_chain("scan-2"))

    body, _ = call({"limit": 10, "cursor": cursor}, scan=_no_host_scan)

    assert body["error"]["code"] == "AGENTBOM_MCP_CONFLICT_STALE_CURSOR", body
    assert body["error"]["category"] == "conflict"


def test_cursor_from_another_tenant_is_rejected(paged, monkeypatch):
    store, call = paged
    first, _ = call({"limit": 10}, scan=_no_host_scan)
    payload = json.loads(base64.urlsafe_b64decode(first["pagination"]["next_cursor"]))
    other = _chain()
    other.tenant_id = "other-tenant"
    store.save_graph(other)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "other-tenant")
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

    body, _ = call({"limit": 10, "cursor": forged}, scan=_no_host_scan)

    assert body["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"


def test_a_page_that_exceeds_the_response_budget_shrinks_instead_of_lying(paged, monkeypatch):
    from agent_bom import mcp_server

    _store, call = paged
    monkeypatch.setattr(mcp_server, "_MAX_RESPONSE_CHARS", 4_000)
    body, _ = call({"limit": 23}, scan=_no_host_scan)

    assert "_truncated" not in json.dumps(body)
    assert body["completeness"]["complete"] is False
    assert body["completeness"]["returned"] == len(_owned(body)) < NODES
    assert body["pagination"]["next_cursor"]


def test_pages_report_stored_times_never_the_read_clock(export, monkeypatch):  # noqa: F811 - fixture
    from agent_bom.graph import container as container_module
    from agent_bom.graph import edge as edge_module
    from agent_bom.graph import node as node_module
    from agent_bom.mcp_tools.graph_export_persisted import _read_page

    store, call = export
    # Keep the evidence inside retention regardless of when this test runs.
    stored_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    graph = _chain()
    graph.created_at = stored_time
    for node in graph.nodes.values():
        node.first_seen = node.last_seen = stored_time
    store.save_graph(graph)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    read_clock = "2099-01-01T00:00:00+00:00"
    for module in (node_module, edge_module, container_module):
        monkeypatch.setattr(module, "_now_iso", lambda: read_clock)

    page = _read_page(store, TENANT, None, 10)
    assert isinstance(page, tuple)
    assert all(node.first_seen == node.last_seen == stored_time for node in page[0].nodes.values())
    body, _scans = call({"limit": 10}, scan=_no_host_scan)

    assert any((node.get("attributes") or {}).get("page_reference") for node in body["nodes"])
    for node in body["nodes"]:
        assert read_clock not in (node.get("first_seen"), node.get("last_seen")), node
    assert read_clock not in json.dumps(body)
