"""Exact native identifiers require tenant/source scope and a stable snapshot."""

from types import SimpleNamespace

import pytest

from agent_bom.api.trace_inventory_correlation import correlate_inventory_observations


def observation(**changes):
    metadata = {"inventory_node_id": "function:exact", "cloud_provider": "aws", "account_id": "111111111111", "environment": "production"}
    metadata.update(changes)
    return {"tenant_id": "tenant-a", "observation_id": "span-1", "surface": "imported_trace", "metadata": metadata}


class Store:
    def __init__(self, *, changed=False, **attributes):
        self.reads = 0
        self.changed = changed
        self.attributes = {"cloud_provider": "aws", "account_id": "111111111111", "environment": "production", **attributes}

    def snapshot_identity(self, **kwargs):
        assert kwargs["tenant_id"] == "tenant-a"
        self.reads += 1
        return "snapshot", "new" if self.changed and self.reads > 1 else "generation"

    def nodes_by_ids(self, **kwargs):
        assert kwargs["tenant_id"] == "tenant-a"
        return (
            [
                SimpleNamespace(
                    id="function:exact", attributes=self.attributes, dimensions=SimpleNamespace(cloud_provider="", environment="")
                )
            ]
            if "function:exact" in kwargs["node_ids"]
            else []
        )


def test_exact_identity_join_is_not_an_execution_or_exploit_claim():
    result = correlate_inventory_observations(Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[observation()])
    assert result["span-1"]["state"] == "exact_identifier"
    assert result["span-1"]["snapshot_generation"] == "generation"
    assert result["span-1"]["execution_proven"] is False
    assert result["span-1"]["basis"] == "source_reported_canonical_id"


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": "222222222222"},
        {"environment": "development"},
        {"cloud_provider": "gcp"},
        {"account_id": ""},
        {"inventory_node_id": "same display name"},
    ],
)
def test_names_missing_scope_and_other_environments_do_not_join(change):
    result = correlate_inventory_observations(Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[observation(**change)])
    assert result["span-1"]["state"] != "exact_identifier"


def test_wrong_tenant_is_never_resolved():
    row = observation()
    row["tenant_id"] = "tenant-b"
    assert correlate_inventory_observations(Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[row]) == {}


def test_snapshot_replacement_invalidates_the_entire_read():
    result = correlate_inventory_observations(Store(changed=True), tenant_id="tenant-a", scan_id="snapshot", observations=[observation()])
    assert result["span-1"]["state"] == "snapshot_changed"
    assert "node_id" not in result["span-1"]


def test_durable_native_import_correlates_only_the_bound_snapshot(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.native_trace_import import TraceImportScope
    from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore
    from agent_bom.api.trace_import_service import import_native_pages
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
    from agent_bom.runtime.native_trace_spans import native_span
    from agent_bom.trace_connectors import NativeTracePage

    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant-a")
    graph.add_node(
        UnifiedNode(
            id="function:exact",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="Invoice function",
            attributes={
                "cloud_provider": "aws",
                "account_id": "111111111111",
                "environment": "production",
            },
        )
    )
    graph_store.save_graph(graph)
    span = native_span(
        {
            "id": "call",
            "traceId": "trace",
            "name": "arbitrary display name",
            "type": "TOOL",
            "metadata": {"agent_bom.inventory_node_id": "function:exact", "account_id": "spoofed"},
        },
        provider="langfuse",
        include_content=False,
    )
    database = str(tmp_path / "traces.db")
    scope = TraceImportScope(
        tenant_id="tenant-a",
        provider="langfuse",
        connection_id="connection",
        endpoint="https://example.test",
        project_id="project",
        cloud_provider="aws",
        account_id="111111111111",
        environment="production",
    )
    import_native_pages(SQLiteRuntimeEventStore(database), scope=scope, fetch=lambda **kw: NativeTracePage({"spans": [span]}, None, 1))
    retained = [r.to_dict() for r in SQLiteRuntimeEventStore(database).list_observations("tenant-a")]
    binding = correlate_inventory_observations(graph_store, tenant_id="tenant-a", scan_id="snapshot", observations=retained)
    assert binding[retained[0]["observation_id"]]["state"] == "exact_identifier"
    assert retained[0]["metadata"]["account_id"] == "111111111111"
    missing = correlate_inventory_observations(graph_store, tenant_id="tenant-a", scan_id="missing", observations=retained)
    assert missing[retained[0]["observation_id"]]["state"] == "snapshot_unavailable"


@pytest.mark.parametrize(
    "metadata", [None, ["malformed"], {"inventory_node_id": []}, {"inventory_node_id": "function:exact", "account_id": []}]
)
def test_malformed_identity_claim_does_not_break_explorer(metadata):
    row = {**observation(), "metadata": metadata}
    result = correlate_inventory_observations(Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[row])
    assert result["span-1"]["state"] != "exact_identifier"


@pytest.mark.parametrize("pin", [{"inventory_scan_id": "older"}, {"inventory_generation": "replaced"}])
def test_source_snapshot_claim_cannot_bind_to_another_generation(pin):
    result = correlate_inventory_observations(Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[observation(**pin)])
    assert result["span-1"]["state"] == "snapshot_conflict"
    assert "node_id" not in result["span-1"]


def test_cloud_origin_scope_is_resolved_without_losing_conflicting_aliases():
    store = Store(account_id=None, cloud_origin={"provider": "aws", "scope": {"account_id": "111111111111"}})
    result = correlate_inventory_observations(store, tenant_id="tenant-a", scan_id="snapshot", observations=[observation()])
    assert result["span-1"]["state"] == "exact_identifier"
    store.attributes["scope"] = {"account_id": "222222222222"}
    result = correlate_inventory_observations(store, tenant_id="tenant-a", scan_id="snapshot", observations=[observation()])
    assert result["span-1"]["state"] == "scope_conflict"


@pytest.mark.parametrize("state", ["conflict", "invalid"])
def test_cloud_trace_scope_conflict_blocks_otherwise_exact_inventory_identifier(state):
    result = correlate_inventory_observations(
        Store(), tenant_id="tenant-a", scan_id="snapshot", observations=[observation(cloud_trace={"scope_state": state})]
    )
    assert result["span-1"]["state"] == "scope_conflict"
    assert "node_id" not in result["span-1"]
