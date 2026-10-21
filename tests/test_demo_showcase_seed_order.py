"""A fresh demo boot never serves the baseline as the default graph while the current snapshot is still being built."""

from __future__ import annotations

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID, SHOWCASE_SCAN_ID, seed_showcase_graph_if_empty


def test_every_intermediate_default_read_is_the_current_showcase(tmp_path):
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    served: list[str] = []
    save = store.save_graph

    def observed_save(graph, *args, **kwargs):
        result = save(graph, *args, **kwargs)
        served.append(store.latest_snapshot_id(tenant_id="default", snapshot_kind="scan"))
        return result

    store.save_graph = observed_save  # type: ignore[method-assign]
    assert seed_showcase_graph_if_empty(store, tenant_id="default")
    assert served and set(served) == {SHOWCASE_SCAN_ID}, served
    ids = {row["scan_id"] for row in store.list_snapshots(tenant_id="default", limit=10)}
    assert ids == {SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID}
