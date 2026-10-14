"""Relationship contract: every edge kind has a spec, every produced edge obeys it.

The probe estate combines every real producer family the repo can build offline
(multi-cloud report, self-scan inventory, project scan, showcase, enterprise
demo estate). Building it must yield zero contract violations and zero edges
without ``evidence.source`` / ``evidence.tier``.
"""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.api.routes.graph_routes.schema_meta import _RELATIONSHIP_SCHEMA_META
from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
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
from tests.test_graph_schema_emission_honesty import REPORT

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _cli_report(args: list[str], output: Path) -> dict:
    result = CliRunner().invoke(main, [*args, "-o", str(output)])
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text())


def _probe_graphs(tmp: Path) -> dict[str, UnifiedGraph]:
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations
    from agent_bom.demo_estate.enterprise_findings import build_estate_findings
    from agent_bom.demo_estate.estate_graph import project_estate_into_graph
    from agent_bom.demo_estate.showcase_graph import (
        apply_showcase_overlays,
        build_showcase_graph,
        finalize_showcase_snapshot,
        project_estate_onto_showcase,
    )

    showcase, store, drift = build_showcase_graph()
    apply_showcase_overlays(showcase, identity_store=store, drift_store=drift)
    finalize_showcase_snapshot(showcase, profile="current")
    project_estate_onto_showcase(showcase, tenant_id="default", profile="current")
    estate = build_demo_estate(tenant_id="default")
    estate_graph = UnifiedGraph(scan_id="estate", tenant_id="default")
    project_estate_into_graph(estate_graph, estate, findings=build_estate_findings(estate), correlations=build_estate_correlations(estate))
    project = json.loads((FIXTURES / "scan_characterization" / "project_json.json").read_text())["document"]
    demo = _cli_report(["scan", "--demo", "--offline", "-f", "json", "--exit-zero"], tmp / "demo.json")
    sample = tmp / "quickstart"
    assert CliRunner().invoke(main, ["quickstart", "--write-sample", "--sample-dir", str(sample), "--offline"]).exit_code == 0
    quickstart = _cli_report(
        [
            "agents",
            "--inventory",
            str(sample / "inventory.json"),
            "-p",
            str(sample),
            "--context-graph",
            "--exit-zero",
            "--scan-prompts",
            "--agent-project",
            str(sample),
            "--ai-inventory",
            str(sample),
            "--offline",
            "--no-scan",
        ],
        tmp / "quickstart.json",
    )
    lab = json.loads((ROOT / "examples" / "reference-evidence-lab" / "generated" / "correlation-proof.json").read_text())
    graphs = {
        "multi_cloud_report": build_unified_graph_from_report(REPORT),
        "self_scan": build_unified_graph_from_report(json.loads((FIXTURES / "agent_bom_self_scan_inventory.json").read_text())),
        "project_scan": build_unified_graph_from_report(project),
        "demo_scan": build_unified_graph_from_report(demo),
        "quickstart": build_unified_graph_from_report(quickstart),
        "showcase": showcase,
        "demo_estate": estate_graph,
        "reference_lab": UnifiedGraph.from_dict(lab["capture_fixture"]["graph"]),
    }
    for name, report in json.loads((FIXTURES / "graph_cloud_context" / "reports.json").read_text()).items():
        graphs[f"cloud:{name}"] = build_unified_graph_from_report(report)
    return graphs


@pytest.fixture(scope="module")
def probe_graphs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, UnifiedGraph]:
    with pytest.MonkeyPatch.context() as mp:
        # Warn mode so every violation reaches the audit instead of aborting a
        # producer whose failures an overlay would swallow.
        mp.setenv("AGENT_BOM_GRAPH_CONTRACT", "warn")
        return _probe_graphs(tmp_path_factory.mktemp("contract-probe"))


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


def test_probe_estate_has_no_contract_violations(probe_graphs: dict[str, UnifiedGraph], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_CONTRACT", "warn")
    edges = 0
    for name, graph in probe_graphs.items():
        summary = audit_graph_contract(graph, record=False)
        edges += summary["edges_checked"]
        assert summary["violations"] == {}, f"{name}: {summary['pairs']}"
    assert edges > 20_000, "the probe estate shrank and stopped proving anything"


def test_probe_estate_covers_every_producer_family(probe_graphs: dict[str, UnifiedGraph]) -> None:
    for name, graph in probe_graphs.items():
        assert graph.edges, f"{name} produced no edges"
    assert {"cloud:aws", "cloud:azure", "cloud:gcp", "cloud:snowflake"} <= set(probe_graphs)


def test_regenerated_reference_lab_edges_carry_recorded_evidence(probe_graphs: dict[str, UnifiedGraph]) -> None:
    tiers = {edge.evidence["tier"] for edge in probe_graphs["reference_lab"].edges}
    assert LEGACY_TIER not in tiers
    assert {"modeled_infrastructure", "static_evidence", "runtime_observed"} <= tiers


def test_demo_estate_incident_hops_are_trace_steps(probe_graphs: dict[str, UnifiedGraph]) -> None:
    graph = probe_graphs["demo_estate"]
    hops = [edge for edge in graph.edges if edge.evidence.get("correlation_id")]
    assert hops and all(edge.relationship is RelationshipType.TRACE_STEP for edge in hops)
    assert all(edge.evidence["tier"] == "recorded" for edge in hops)
    hop_ids = {edge.id for edge in hops}
    chains = [path for path in graph.attack_paths if path.edges and path.edges[0].startswith("trace_step:")]
    assert chains and all(set(path.edges) <= hop_ids for path in chains)


def test_no_probe_edge_lacks_evidence_source_or_tier(probe_graphs: dict[str, UnifiedGraph]) -> None:
    missing = [
        (name, edge.id)
        for name, graph in probe_graphs.items()
        for edge in graph.edges
        if not edge.evidence.get("source") or not edge.evidence.get("tier")
    ]
    assert missing == []


def test_probe_estate_covers_most_relationship_kinds(probe_graphs: dict[str, UnifiedGraph]) -> None:
    kinds = {edge.relationship for graph in probe_graphs.values() for edge in graph.edges}
    assert len(kinds) >= 28


def test_builder_records_contract_status(probe_graphs: dict[str, UnifiedGraph]) -> None:
    status = probe_graphs["multi_cloud_report"].analysis_status[ANALYSIS_KEY].to_dict()
    assert status["status"] == "complete"
    assert status["observed"]["edges_checked"] == len(probe_graphs["multi_cloud_report"].edges)


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


def test_suite_runs_the_contract_in_strict_mode() -> None:
    from agent_bom.graph.relationship_contract import contract_mode

    assert contract_mode() == "strict"
