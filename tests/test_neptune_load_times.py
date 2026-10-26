"""A Neptune-loaded graph reports the stored snapshot time, never the time it was read."""

from __future__ import annotations

from typing import Any

from agent_bom.api.neptune_graph import NeptuneGraphStore

STORED_AT = "2026-05-01T00:00:00+00:00"
READ_CLOCK = "2099-01-01T00:00:00+00:00"


class _ScriptedGremlinClient:
    def submit(self, query: str, bindings: dict[str, Any] | None = None) -> list[Any]:
        if "abom_snapshot" in query:
            return [{"scan_id": ["s1"], "tenant_id": ["default"], "created_at": [STORED_AT], "analysis_status_json": ["{}"]}]
        if "abom_node" in query:
            return [
                {"node_id": ["agent:a"], "entity_type": ["agent"], "label": ["a"]},
                {"node_id": ["tool:t"], "entity_type": ["tool"], "label": ["t"]},
            ]
        if query.startswith("g.E()"):
            return [{"source_id": ["agent:a"], "target_id": ["tool:t"], "relationship": ["uses"], "valid_from": [""]}]
        return []


def test_legacy_rows_load_with_the_snapshot_time(monkeypatch):
    from agent_bom.graph import container as container_module
    from agent_bom.graph import edge as edge_module
    from agent_bom.graph import node as node_module

    for module in (node_module, edge_module, container_module):
        monkeypatch.setattr(module, "_now_iso", lambda: READ_CLOCK)

    monkeypatch.setenv("AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH", "1")
    monkeypatch.setenv("AGENT_BOM_NEPTUNE_ENDPOINT", "wss://graph.example.test:8182/gremlin")
    graph = NeptuneGraphStore(client=_ScriptedGremlinClient()).load_graph(tenant_id="default", scan_id="s1")

    assert graph.created_at == STORED_AT
    assert {(node.first_seen, node.last_seen) for node in graph.nodes.values()} == {(STORED_AT, STORED_AT)}
    assert [(edge.first_seen, edge.valid_from) for edge in graph.edges] == [(STORED_AT, STORED_AT)]
