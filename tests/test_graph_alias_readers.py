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
INVENTORY_ID = f"cloud_resource:aws:ec2:instance:scoped/{ACCOUNT}/{REGION}//native/{INSTANCE}"


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
    body = (
        TestClient(app).get("/v1/graph/diff", params={"old": "scan-a", "new": "scan-b", "view": "detail", "node_id": INVENTORY_ID}).json()
    )
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
    second = client.get(
        "/v1/graph/diff", params={**params, "cursor": first["pagination"]["next_cursor"]} if first["pagination"]["next_cursor"] else params
    )
    assert second.status_code == 200
    assert calls == [("scan-a", "scan-b")]

    store.save_graph(build_unified_graph_from_report(_report("dev"), scan_id="scan-b", tenant_id="default"))
    client.get("/v1/graph/diff", params=params)
    assert len(calls) == 2


_VOLATILE = {"resolved_from", "elapsed_ms", "generated_at", "resolved_roots", "assessed_at"}


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


@pytest.mark.parametrize("scan_id", ["scan-b", None])
@pytest.mark.parametrize(
    ("name", "build"),
    [
        ("impact", lambda node: ("/v1/graph/impact", {"node": node})),
        ("paths", lambda node: ("/v1/graph/paths", {"source_id": node})),
        ("node-neighbors", lambda node: ("/v1/graph/node-neighbors", {"node_id": node})),
        ("node/neighbors", lambda node: (f"/v1/graph/node/{node}/neighbors", {})),
        ("rollup", lambda node: ("/v1/graph/rollup", {"node": node})),
    ],
)
def test_node_addressed_reads_resolve_a_replaced_id(store: SQLiteGraphStore, name: str, build: Any, scan_id: str | None) -> None:
    client = TestClient(app)
    extra = {"scan_id": scan_id} if scan_id else {}
    alias_path, alias_params = build(INVENTORY_ID)
    # The canonical id carries ``/``, which a path segment cannot hold; the
    # query-string twin of that route answers for it.
    canonical_path, canonical_params = (
        build(CANONICAL) if name != "node/neighbors" else ("/v1/graph/node-neighbors", {"node_id": CANONICAL})
    )
    by_alias = client.get(alias_path, params={**alias_params, **extra})
    by_canonical = client.get(canonical_path, params={**canonical_params, **extra})
    assert by_canonical.status_code == 200, by_canonical.text
    assert by_alias.status_code == 200, f"{name}: {by_alias.text}"
    alias_body = by_alias.json()
    assert alias_body.get("resolved_from") == INVENTORY_ID, name
    assert by_canonical.json().get("resolved_from") is None, name
    assert _stable(alias_body) == _stable(by_canonical.json()), name
    if name in {"node-neighbors", "node/neighbors"}:
        assert alias_body["found"] is True and alias_body["node_id"] == CANONICAL
        assert alias_body["neighbors"], "the resolved node keeps its audit-trail neighbor"


def test_graph_query_roots_resolve_replaced_ids(store: SQLiteGraphStore) -> None:
    client = TestClient(app)
    payload = {"roots": [INVENTORY_ID], "scan_id": "scan-b", "direction": "both", "max_depth": 2}
    by_alias = client.post("/v1/graph/query", json=payload)
    by_canonical = client.post("/v1/graph/query", json={**payload, "roots": [CANONICAL]})
    assert by_canonical.status_code == 200, by_canonical.text
    assert by_alias.status_code == 200, by_alias.text
    body = by_alias.json()
    assert body["resolved_roots"] == {INVENTORY_ID: CANONICAL}
    assert by_canonical.json()["resolved_roots"] == {}
    assert _stable(body) == _stable(by_canonical.json())


def test_graph_query_unknown_root_still_404s(store: SQLiteGraphStore) -> None:
    response = TestClient(app).post("/v1/graph/query", json={"roots": ["agent:nope"], "scan_id": "scan-b"})
    assert response.status_code == 404
    assert response.json()["detail"]["missing_roots"] == ["agent:nope"]


def test_mcp_exposure_paths_target_resolves_a_replaced_id(store: SQLiteGraphStore) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    def call(target: str) -> dict[str, Any]:
        return json.loads(asyncio.run(exposure_paths_impl(target_id=target, scan_id="scan-b", limit=50, _get_graph_store=lambda: store)))

    by_alias, by_canonical = call(INVENTORY_ID), call(CANONICAL)
    assert "error" not in by_canonical, by_canonical
    assert by_alias.get("total") == by_canonical.get("total")


@pytest.mark.parametrize("path", ["/v1/graph/compromise", "/v1/graph/consequences"])
def test_assessment_roots_resolve_replaced_ids(store: SQLiteGraphStore, path: str) -> None:
    client = TestClient(app)
    payload = {"root_node_id": INVENTORY_ID, "scan_id": "scan-b", "assume_control": True}
    by_alias = client.post(path, json=payload)
    by_canonical = client.post(path, json={**payload, "root_node_id": CANONICAL})
    assert by_canonical.status_code != 404, by_canonical.text
    assert by_alias.status_code == by_canonical.status_code, by_alias.text
    if by_canonical.status_code == 200:
        assert _stable(by_alias.json()) == _stable(by_canonical.json())


def test_graph_paths_page_order_is_backend_independent(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    emitted = [["s", "b", "c"], ["s", "a"], ["s", "b"], ["s", "a", "z"]]

    def fake_bfs(**_kwargs: Any) -> Any:
        return list(reversed(emitted)), {"a", "b", "c", "z"}, False, False

    monkeypatch.setattr(store, "bfs_paths", fake_bfs)
    body = TestClient(app).get("/v1/graph/paths", params={"source_id": CANONICAL, "scan_id": "scan-b", "limit": 2}).json()
    assert [p["hops"] for p in body["paths"]] == [["s", "a"], ["s", "b"]]
    second = TestClient(app).get("/v1/graph/paths", params={"source_id": CANONICAL, "scan_id": "scan-b", "limit": 2, "offset": 2}).json()
    assert [p["hops"] for p in second["paths"]] == [["s", "a", "z"], ["s", "b", "c"]]


def test_scenario_operations_resolve_replaced_ids(store: SQLiteGraphStore) -> None:
    from agent_bom.api.graph_node_alias import resolve_scenario_aliases

    scenario = {
        "id": "s1",
        "operations": [
            {"kind": "patch_node", "node_id": INVENTORY_ID, "patch": {"risk_score": 1.0}},
            {"kind": "add_edge", "source": "proposal:waf", "target": INVENTORY_ID, "relationship": "protects"},
        ],
    }
    resolved = resolve_scenario_aliases(store, "default", "scan-b", scenario)
    assert resolved["operations"][0]["node_id"] == CANONICAL
    assert resolved["operations"][1] == {**scenario["operations"][1], "target": CANONICAL}
    assert scenario["operations"][0]["node_id"] == INVENTORY_ID, "the stored scenario is not mutated"
