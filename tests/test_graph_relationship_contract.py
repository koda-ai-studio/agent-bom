"""Relationship contract: every edge kind has a spec, every produced edge obeys it.

The probe estate combines every real producer family the repo can build offline
(multi-cloud report, self-scan inventory, project scan, showcase, enterprise
demo estate). Building it must yield zero contract violations and zero edges
without ``evidence.source`` / ``evidence.tier``.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from agent_bom.api.routes.graph_routes.schema_meta import _RELATIONSHIP_SCHEMA_META
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import LEGACY_TIER, edge_evidence, recorded_tier
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.relationship_contract import (
    ANALYSIS_KEY,
    RelationshipContractError,
    audit_graph_contract,
    validate_edge,
)
from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS, TraversalClass
from agent_bom.graph.types import EntityType, RelationshipType

ROOT = Path(__file__).resolve().parents[1]


def test_every_relationship_type_has_a_spec() -> None:
    assert set(RELATIONSHIP_SPECS) == set(RelationshipType)
    for spec in RELATIONSHIP_SPECS.values():
        assert spec.allowed_pairs, spec.rel
        assert {"source", "tier"} <= set(spec.required_evidence)
        assert isinstance(spec.traversal_class, TraversalClass)


def test_correlation_relationships_are_not_traversable_by_default() -> None:
    for rel in (
        RelationshipType.SHARES_SERVER,
        RelationshipType.SHARES_CRED,
        RelationshipType.CORRELATES_WITH,
        RelationshipType.POSSIBLY_CORRELATES_WITH,
    ):
        assert RELATIONSHIP_SPECS[rel].traversal_class is TraversalClass.CORRELATION
        assert RELATIONSHIP_SPECS[rel].default_traversable is False


def _edge_constructor_relationships() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "src" / "agent_bom").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if func not in {"UnifiedEdge", "_add_rel_edge", "edge", "_edge", "_ensure_showcase_edge"}:
                continue
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "RelationshipType":
                        names.add(sub.attr)
    return names


def test_every_relationship_used_by_an_edge_constructor_has_a_spec() -> None:
    used = _edge_constructor_relationships()
    assert len(used) > 30, "the AST scan stopped finding edge constructors"
    missing = sorted(name for name in used if RelationshipType[name] not in RELATIONSHIP_SPECS)
    assert not missing


def test_schema_meta_is_derived_from_the_registry() -> None:
    for rel, spec in RELATIONSHIP_SPECS.items():
        meta = _RELATIONSHIP_SCHEMA_META[rel.value]
        assert meta["traversal_class"] == spec.traversal_class.value
        assert meta["required_evidence"] == list(spec.required_evidence)
        assert meta["traversable"] is spec.default_traversable
        pairs = {(pair[0], pair[1]) for pair in meta["allowed_pairs"]}
        assert pairs == {(s.value, t.value) for s, t in spec.allowed_pairs}
        assert {s for s, _ in pairs} == set(meta["source_types"])
        assert {t for _, t in pairs} == set(meta["target_types"])


def _two_node_graph(src: EntityType, tgt: EntityType) -> UnifiedGraph:
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="a", entity_type=src, label="a"))
    graph.add_node(UnifiedNode(id="b", entity_type=tgt, label="b"))
    return graph


def test_strict_mode_rejects_a_disallowed_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "strict")
    graph = _two_node_graph(EntityType.USER, EntityType.ROLE)
    with pytest.raises(RelationshipContractError, match="pair_not_allowed"):
        graph.add_edge(UnifiedEdge("a", "b", RelationshipType.TRUSTS, evidence=edge_evidence("t", "recorded")))
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.ASSUMES, evidence=edge_evidence("t", "recorded")))
    assert len(graph.edges) == 1


def test_warn_mode_keeps_the_edge_and_logs_once(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "warn")
    graph = _two_node_graph(EntityType.TOOL_CALL, EntityType.CLUSTER)
    graph.add_node(UnifiedNode(id="c", entity_type=EntityType.CLUSTER, label="c"))
    with caplog.at_level(logging.WARNING, logger="agent_bom.graph.relationship_contract"):
        graph.add_edge(UnifiedEdge("a", "b", RelationshipType.INVOKED, evidence=edge_evidence("t", "recorded")))
        graph.add_edge(UnifiedEdge("a", "c", RelationshipType.INVOKED, evidence=edge_evidence("t", "recorded")))
    assert len(graph.edges) == 2
    assert sum("invoked tool_call -> cluster" in record.getMessage() for record in caplog.records) == 1
    summary = audit_graph_contract(graph)
    assert summary["violations"] == {"pair_not_allowed": 2}
    status = graph.analysis_status[ANALYSIS_KEY].to_dict()
    assert status["status"] == "limited" and status["observed"]["pair_not_allowed"] == 2


def test_enforce_mode_drops_the_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "enforce")
    graph = _two_node_graph(EntityType.USER, EntityType.ROLE)
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.TRUSTS, evidence=edge_evidence("t", "recorded")))
    assert graph.edges == []


def test_validate_edge_reports_evidence_and_dangling_problems() -> None:
    bare = UnifiedEdge("a", "b", RelationshipType.USES)
    assert validate_edge(bare, EntityType.AGENT, EntityType.SERVER) == ["missing_evidence_source", "missing_evidence_tier"]
    assert "dangling_endpoint" in validate_edge(bare, None, EntityType.SERVER)
    derived = UnifiedEdge("a", "b", RelationshipType.LATERAL_PATH, evidence={"source": "graph-analysis", "tier": "derived"})
    assert validate_edge(derived, EntityType.AGENT, EntityType.AGENT) == ["derived_without_derived_via"]


def test_edge_evidence_helper_contract() -> None:
    assert edge_evidence("cloud-inventory", "modeled_infrastructure", basis="config", region="x") == {
        "source": "cloud-inventory",
        "tier": "modeled_infrastructure",
        "basis": "config",
        "region": "x",
    }
    with pytest.raises(ValueError, match="derived_via"):
        edge_evidence("graph-analysis", "derived")
    with pytest.raises(ValueError, match="tier"):
        edge_evidence("x", "made-up")
    assert edge_evidence("graph-analysis", "derived", derived_via="shares_server")["derived_via"] == "shares_server"


def test_known_collector_source_gets_its_tier_on_add() -> None:
    graph = _two_node_graph(EntityType.ACCOUNT, EntityType.CLOUD_RESOURCE)
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.CONTAINS, evidence={"source": "cloud-inventory"}))
    assert graph.edges[0].evidence["tier"] == "modeled_infrastructure"


def test_merge_unions_provenance_and_keeps_max_confidence() -> None:
    graph = _two_node_graph(EntityType.AGENT, EntityType.SERVER)
    ev = edge_evidence("mcp-scan", "static_scan")
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.USES, evidence=ev, confidence=0.4, provenance={"source": "scan-a"}))
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.USES, evidence=ev, confidence=0.9, provenance={"source": "scan-b"}))
    stored = graph.edges[0]
    assert stored.confidence == 0.9
    assert stored.provenance["sources"] == ["scan-a", "scan-b"]


def test_pre_envelope_edges_read_as_legacy_unrecorded() -> None:
    assert recorded_tier({}) == LEGACY_TIER
    assert recorded_tier({"source": "cloud-inventory"}) == LEGACY_TIER
    assert recorded_tier({"source": "cloud-inventory", "tier": "modeled_infrastructure"}) == "modeled_infrastructure"


def test_graph_json_rehydration_loads_stored_edges_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "enforce")
    payload = _two_node_graph(EntityType.AGENT, EntityType.SERVER).to_dict()
    payload["edges"] = [
        {"source": "a", "target": "b", "relationship": "uses"},
        # An out-of-contract pair persisted before the contract still loads as stored.
        {"source": "b", "target": "a", "relationship": "trusts"},
    ]
    graph = UnifiedGraph.from_dict(payload)
    assert {edge.relationship for edge in graph.edges} == {RelationshipType.USES, RelationshipType.TRUSTS}
    assert all(edge.evidence == {} for edge in graph.edges)
    assert graph.contract_admission is True
    graph.add_node(UnifiedNode(id="c", entity_type=EntityType.USER, label="c"))
    graph.add_edge(UnifiedEdge("c", "b", RelationshipType.TRUSTS, evidence=edge_evidence("t", "recorded")))
    assert len(graph.edges) == 2, "admission is back on for producer edges after the load"


def test_sqlite_round_trip_keeps_stored_evidence_and_out_of_contract_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3

    from agent_bom.api.graph_store import SQLiteGraphStore

    db = tmp_path / "graph.db"
    store = SQLiteGraphStore(db)
    graph = _two_node_graph(EntityType.AGENT, EntityType.SERVER)
    graph.scan_id = "legacy"
    graph.add_edge(UnifiedEdge("a", "b", RelationshipType.USES, evidence=edge_evidence("mcp-scan", "static_scan")))
    store.save_graph(graph)
    assert [edge.evidence for edge in store.load_graph(scan_id="legacy").edges] == [{"source": "mcp-scan", "tier": "static_scan"}]
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE graph_edges SET evidence = '{}', relationship = 'trusts'")
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "enforce")
    loaded = store.load_graph(scan_id="legacy")
    assert [(edge.relationship, edge.evidence) for edge in loaded.edges] == [(RelationshipType.TRUSTS, {})]
    assert recorded_tier(loaded.edges[0].evidence) == LEGACY_TIER
