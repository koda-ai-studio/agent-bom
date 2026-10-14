"""Graph read routes serve the snapshot path index with derive-on-read parity."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import AttackPath
from agent_bom.graph import snapshot_paths as snapshot_paths_module
from agent_bom.graph.builder import build_unified_graph_from_report
from tests.graph.test_snapshot_paths import shared_server_estate

SCAN = "route-scan"
VOLATILE = {"snapshot_generation", "created_at", "computed_at", "generated_at", "request_id"}


def _strip(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _strip(item) for key, item in value.items() if key not in VOLATILE}
    if isinstance(value, list):
        return [_strip(item) for item in value]
    return value


@pytest.fixture()
def indexed_store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = build_unified_graph_from_report(shared_server_estate(agents=30, group_size=10), scan_id=SCAN, tenant_id="default")
    store.save_graph(graph)
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


def _get(path: str, **params: Any) -> dict[str, Any]:
    response = TestClient(app).get(path, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _force_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.graph.snapshot_paths import DERIVATION_VERSION

    monkeypatch.setattr(snapshot_paths_module, "DERIVATION_VERSION", DERIVATION_VERSION + 1)


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/v1/graph/attack-paths", {"scan_id": SCAN, "limit": 25}),
        ("/v1/graph/attack-paths", {"scan_id": SCAN, "limit": 7, "min_severity": "high"}),
        ("/v1/graph/attack-paths", {"scan_id": SCAN, "limit": 10, "has_credential": "true", "source_type": "agent"}),
        ("/v1/graph/views/fix-first", {"scan_id": SCAN, "limit": 8}),
        ("/v1/graph/views/fix-first", {"scan_id": SCAN, "limit": 3, "cve": "CVE-2026-00010"}),
        ("/v1/graph/governance", {"scan_id": SCAN}),
        ("/v1/graph/exposure-paths", {"scan_id": SCAN, "limit": 5}),
        ("/v1/graph/rollup", {"scan_id": SCAN, "mode": "attack_path"}),
    ],
)
def test_stored_index_matches_derive_on_read(indexed_store, monkeypatch, path, params) -> None:
    calls: list[int] = []
    real_derive = snapshot_paths_module._derive_on_read
    monkeypatch.setattr(snapshot_paths_module, "_derive_on_read", lambda graph: calls.append(1) or real_derive(graph))
    stored = _get(path, **params)
    assert calls == []

    _force_fallback(monkeypatch)
    from agent_bom.api import graph_rollup_cache

    monkeypatch.setattr(graph_rollup_cache, "_CACHE", type(graph_rollup_cache._CACHE)())
    derived = _get(path, **params)
    assert _strip(stored) == _strip(derived)


def test_attack_path_queue_never_loads_the_graph_when_indexed(indexed_store, monkeypatch) -> None:
    def no_full_load(**_kwargs: Any) -> Any:
        raise AssertionError("indexed queue must not load the whole graph")

    monkeypatch.setattr(indexed_store, "load_graph", no_full_load)
    body = _get("/v1/graph/attack-paths", scan_id=SCAN, limit=5)
    assert body["pagination"]["total"] == body["count_metadata"]["snapshot_total"] > 5
    assert body["count_metadata"]["source"] == "derived_graph_paths"


def test_queue_and_graph_page_include_derived_paths_beside_fusion_rows(tmp_path, monkeypatch) -> None:
    """Fusion rows no longer hide the derived component paths (one path set everywhere)."""
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = build_unified_graph_from_report(shared_server_estate(agents=10, group_size=5), scan_id=SCAN, tenant_id="default")
    agent = next(node_id for node_id in graph.nodes if node_id.startswith("agent:"))
    server = next(node_id for node_id in graph.nodes if node_id.startswith("server:"))
    graph.attack_paths.append(AttackPath(source=agent, target=server, hops=[agent, server], edges=["uses"], composite_risk=5.0))
    store.save_graph(graph)
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        queue = _get("/v1/graph/attack-paths", scan_id=SCAN, limit=500)
        page = _get("/v1/graph", scan_id=SCAN, limit=5000)
    finally:
        set_graph_store(original)

    assert queue["pagination"]["total"] > 1
    queue_keys = {(path["source"], path["target"], tuple(path["hops"])) for path in queue["attack_paths"]}
    page_keys = {(path["source"], path["target"], tuple(path["hops"])) for path in page["attack_paths"]}
    assert (agent, server, (agent, server)) in queue_keys
    assert page_keys == queue_keys
