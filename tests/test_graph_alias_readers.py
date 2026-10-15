"""Readers that take a node id resolve ids a snapshot replaced, and say so."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph.builder import build_unified_graph_from_report

ACCOUNT = "210987654321"
REGION = "us-east-1"
INSTANCE = "i-0a1b2c3d4e5f60718"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{INSTANCE}"
CANONICAL = f"cloud_resource:aws:aws_instance:{ACCOUNT}/{REGION}/{INSTANCE}"
INVENTORY_ID = f"cloud_resource:aws:ec2:instance:{INSTANCE}"


def _report(environment: str = "prod") -> dict[str, Any]:
    return {
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": ACCOUNT,
            "region": REGION,
            "instances": [{"instance_id": INSTANCE, "name": "billing-api", "region": REGION, "tags": {"environment": environment}}],
        },
        "cloud_audit_trail": {
            "status": "ok",
            "provider": "aws",
            "account": ACCOUNT,
            "behavioral_edges": [{"principal": "ops", "resource": ARN, "action": "StopInstances", "relationship": "invoked", "count": 1}],
        },
    }


@pytest.fixture()
def store(tmp_path: Any, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    graph_store = SQLiteGraphStore(tmp_path / "alias-graph.db")
    graph_store.save_graph(build_unified_graph_from_report(_report(), scan_id="scan-a", tenant_id="default"))
    graph_store.save_graph(build_unified_graph_from_report(_report("stage"), scan_id="scan-b", tenant_id="default"))
    original = api_stores._graph_store
    set_graph_store(graph_store)
    try:
        yield graph_store
    finally:
        api_stores._graph_store = original
        reset_backpressure_for_tests()


def test_node_context_resolves_a_replaced_id(store: SQLiteGraphStore) -> None:
    body = TestClient(app).get(f"/v1/graph/node/{INVENTORY_ID}", params={"scan_id": "scan-b"}).json()
    assert body["node"]["id"] == CANONICAL
    assert body["resolved_from"] == INVENTORY_ID


def test_canonical_id_reports_no_resolution(store: SQLiteGraphStore) -> None:
    body = TestClient(app).get("/v1/graph/node-context", params={"node_id": CANONICAL, "scan_id": "scan-b"}).json()
    assert body["node"]["id"] == CANONICAL and body["resolved_from"] is None


def test_incident_edges_resolve_a_replaced_id(store: SQLiteGraphStore) -> None:
    body = TestClient(app).get("/v1/graph/incident-edges", params={"node_id": INVENTORY_ID, "scan_id": "scan-b"}).json()
    assert body["found"] is True
    assert body["node"]["id"] == CANONICAL and body["node_id"] == CANONICAL
    assert body["resolved_from"] == INVENTORY_ID


def test_graph_diff_node_filter_resolves_a_replaced_id(store: SQLiteGraphStore) -> None:
    body = TestClient(app).get("/v1/graph/diff", params={"old": "scan-a", "new": "scan-b", "view": "detail", "node_id": INVENTORY_ID}).json()
    assert body["resolved_from"] == INVENTORY_ID
    assert body["filters"]["node_id"] == CANONICAL


def test_mcp_graph_reach_resolves_a_replaced_id(store: SQLiteGraphStore) -> None:
    from agent_bom.mcp_tools.graph_reach import graph_reach_impl

    payload = json.loads(asyncio.run(graph_reach_impl(node_id=INVENTORY_ID, scan_id="scan-b", _get_graph_store=lambda: store)))
    assert payload["node_id"] == CANONICAL and payload["resolved_from"] == INVENTORY_ID


def test_graph_diff_pages_reuse_one_computed_diff(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import graph_diff_read

    calls: list[tuple[str, str]] = []
    original = store.diff_snapshots

    def counting(old: str, new: str, **kwargs: Any) -> Any:
        calls.append((old, new))
        return original(old, new, **kwargs)

    monkeypatch.setattr(store, "diff_snapshots", counting)
    monkeypatch.setattr(graph_diff_read, "_rows_cache", type(graph_diff_read._rows_cache)())
    client = TestClient(app)
    params = {"old": "scan-a", "new": "scan-b", "view": "detail", "limit": 1}
    first = client.get("/v1/graph/diff", params=params).json()
    second = client.get("/v1/graph/diff", params={**params, "cursor": first["pagination"]["next_cursor"]} if first["pagination"]["next_cursor"] else params)
    assert second.status_code == 200
    assert calls == [("scan-a", "scan-b")]

    store.save_graph(build_unified_graph_from_report(_report("dev"), scan_id="scan-b", tenant_id="default"))
    client.get("/v1/graph/diff", params=params)
    assert len(calls) == 2
