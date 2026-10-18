"""Stored rows without an identity receipt resolve their legacy id on demand.

Hydrating a snapshot built one uuid5 per row up front, even for read paths
(the roll-up) that never read ``canonical_id``. The id must be unchanged; only
when it is computed moves.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_bom import canonical_ids
from agent_bom.canonical_ids import legacy_canonical_id_v2
from agent_bom.graph import UnifiedEdge, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_stored_edge_without_receipt_hashes_only_when_read(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple] = []
    original = canonical_ids.legacy_canonical_id_v2

    def counting(*parts):
        calls.append(parts)
        return original(*parts)

    monkeypatch.setattr("agent_bom.graph.edge.legacy_canonical_id_v2", counting)
    edge = UnifiedEdge.from_stored(source="a", target="b", relationship=RelationshipType.USES)
    assert calls == []
    expected = legacy_canonical_id_v2("graph_edge", "uses", "a", "b")
    assert edge.canonical_id == expected
    assert edge.canonical_id == expected
    assert len(calls) == 1
    # A copy keeps the receipt of the stored row; moved endpoints drop it.
    assert replace(edge, weight=2.0).canonical_id == expected
    assert edge.with_endpoints("a", "c").canonical_id != expected


def test_stored_edge_with_receipt_keeps_it() -> None:
    edge = UnifiedEdge.from_stored(
        source="a", target="b", relationship=RelationshipType.USES, provenance={"_agent_bom_canonical_id": "recorded-id"}
    )
    assert edge.canonical_id == "recorded-id"
    assert "_agent_bom_canonical_id" not in edge.provenance


def test_stored_node_without_receipt_hashes_only_when_read(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple] = []
    original = canonical_ids.legacy_canonical_id_v2
    monkeypatch.setattr("agent_bom.graph.node.legacy_canonical_id_v2", lambda *parts: calls.append(parts) or original(*parts))
    node = UnifiedNode.from_stored(id="agent:x", entity_type=EntityType.AGENT, label="x", attributes={})
    assert calls == []
    assert node.canonical_id == legacy_canonical_id_v2("graph_node", "agent", "agent:x")
    recorded = UnifiedNode.from_stored(
        id="agent:y", entity_type=EntityType.AGENT, label="y", attributes={"_agent_bom_canonical_id": "kept"}
    )
    assert recorded.canonical_id == "kept"
