"""An unpinned /v1/graph read while the demo seed is landing is not ready, never an empty complete graph."""

from __future__ import annotations

import pytest

from tests.test_graph_attack_path_cursor import _three_path_graph
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


@pytest.fixture()
def seeding(monkeypatch):
    from agent_bom.demo_estate import boot_seed

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    boot_seed._boot_seed_done.clear()
    yield boot_seed
    boot_seed._boot_seed_done.set()


def test_unpinned_graph_read_during_demo_seed_is_retryable_not_ready(api, seeding):  # noqa: F811
    client, store, headers = api
    store.save_graph(_three_path_graph("tenant-a"))
    response = client.get("/v1/graph", headers=headers["tenant-a"])
    assert response.status_code == 503, response.text
    assert response.headers["Retry-After"] == "2"
    assert "current_estate_seeding" in response.text
    pinned = client.get("/v1/graph", params={"scan_id": "shared-scan"}, headers=headers["tenant-a"])
    assert pinned.status_code == 200, pinned.text
    seeding._boot_seed_done.set()
    assert client.get("/v1/graph", headers=headers["tenant-a"]).status_code == 200


def test_internal_current_estate_reads_are_not_refused_while_seeding(tmp_path, seeding):
    from agent_bom.api.current_graph import CurrentGraphStore
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.store import InMemoryJobStore

    store = CurrentGraphStore(SQLiteGraphStore(tmp_path / "graph.db"), InMemoryJobStore())
    assert not store.load_graph(tenant_id="default").nodes
