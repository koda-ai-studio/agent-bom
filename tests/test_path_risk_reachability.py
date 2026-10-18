"""Path risk keeps its severity/KEV/exposure order; evidence completeness is a separate qualifier."""

from __future__ import annotations

import json

import pytest

from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.attack_path_queue_rank import attack_path_rank_key, path_rank_fields
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.mcp_tools.graph import deploy_decision_impl


def _graph(*, analysis: GraphAnalysisState | None = GraphAnalysisState.COMPLETE, freshness: str = "unknown") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-1", tenant_id="tenant-a")
    if analysis is not None:
        graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=analysis)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="assistant"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="image-server"))
    graph.add_node(UnifiedNode(id="pkg:pypi:pillow@9.0.0", entity_type=EntityType.PACKAGE, label="pillow@9.0.0"))
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2023-4863",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2023-4863",
            severity="high",
            attributes={"is_kev": True},
        )
    )
    for source, target, rel in (
        ("agent:a", "server:s", RelationshipType.USES),
        ("server:s", "pkg:pypi:pillow@9.0.0", RelationshipType.DEPENDS_ON),
        ("pkg:pypi:pillow@9.0.0", "vuln:CVE-2023-4863", RelationshipType.VULNERABLE_TO),
    ):
        graph.add_edge(
            UnifiedEdge(
                source=source,
                target=target,
                relationship=rel,
                source_scan_id=graph.scan_id,
                provenance={"source": "scanner"},
                evidence={"freshness": freshness},
            )
        )
    return graph


def _path(risk: float = 88.0) -> AttackPath:
    return AttackPath(
        source="agent:a",
        target="vuln:CVE-2023-4863",
        hops=["agent:a", "server:s", "pkg:pypi:pillow@9.0.0", "vuln:CVE-2023-4863"],
        edges=["uses", "depends_on", "vulnerable_to"],
        composite_risk=risk,
        credential_exposure=["AWS_TOKEN"],
        vuln_ids=["CVE-2023-4863"],
    )


def test_incomplete_hop_evidence_qualifies_reachability_without_clamping_risk() -> None:
    graph = _graph(freshness="unknown")
    path = annotate_attack_path_evidence(_path(88.0), graph)
    assert path.composite_risk == 88.0
    assert path.reachability == "unknown"
    assert "incomplete_hop_evidence" in path.reachability_basis


def test_receipts_are_not_truncated_when_analysis_status_is_missing() -> None:
    graph = _graph(analysis=None, freshness="fresh")
    path = annotate_attack_path_evidence(_path(), graph)
    assert path.analysis["status"] == "not_recorded"
    assert [receipt["truncated"] for receipt in path.hop_evidence] == [False, False, False]
    assert all("analysis_not_recorded" in receipt["reason_codes"] for receipt in path.hop_evidence)
    # Analysis that never ran cannot confirm the path even with complete hops.
    assert path.reachability == "unknown"
    assert "analysis_not_recorded" in path.reachability_basis


def test_limited_analysis_is_a_reason_code_not_truncation() -> None:
    graph = _graph(analysis=GraphAnalysisState.LIMITED, freshness="fresh")
    path = annotate_attack_path_evidence(_path(), graph)
    assert [receipt["truncated"] for receipt in path.hop_evidence] == [False, False, False]
    assert all("analysis_limited" in receipt["reason_codes"] for receipt in path.hop_evidence)
    assert path.reachability == "unknown"


def test_reannotation_after_analysis_is_recorded_drops_stale_basis() -> None:
    graph = _graph(analysis=None, freshness="fresh")
    path = annotate_attack_path_evidence(_path(), graph)
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    annotate_attack_path_evidence(path, graph)
    assert path.reachability == "confirmed"
    assert "analysis_not_recorded" not in path.reachability_basis
    assert "incomplete_hop_evidence" not in path.reachability_basis
    assert all(receipt["reason_codes"] == [] for receipt in path.hop_evidence)


def test_component_paths_keep_severity_and_kev_order_in_score() -> None:
    from agent_bom.graph.component_paths import derive_component_paths

    graph = UnifiedGraph(scan_id="scan-1", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="assistant"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server"))
    specs = (("crit", "critical", 9.8, False), ("highkev", "high", 8.8, True), ("high", "high", 8.8, False))
    for name, severity, cvss, kev in specs:
        graph.add_node(UnifiedNode(id=f"pkg:{name}", entity_type=EntityType.PACKAGE, label=name))
        graph.add_node(
            UnifiedNode(
                id=f"vuln:{name}",
                entity_type=EntityType.VULNERABILITY,
                label=f"CVE-{name}",
                severity=severity,
                risk_score=cvss,
                attributes={"is_kev": kev},
            )
        )
        graph.add_edge(UnifiedEdge(source="server:s", target=f"pkg:{name}", relationship=RelationshipType.DEPENDS_ON))
        graph.add_edge(UnifiedEdge(source=f"pkg:{name}", target=f"vuln:{name}", relationship=RelationshipType.VULNERABLE_TO))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    incoming: dict[str, list[UnifiedEdge]] = {}
    outgoing: dict[str, list[UnifiedEdge]] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
        outgoing.setdefault(edge.source, []).append(edge)
    from agent_bom.graph.path_derivation import _node_risk_100

    paths = derive_component_paths(graph, incoming=incoming, outgoing=outgoing, node_risk=_node_risk_100, path_boost=lambda _hops: 0.0)
    risk = {path.target: path.composite_risk for path in paths if path.source == "agent:a"}
    # Same order the queue sorts on: KEV, then severity; no saturated tie.
    assert risk["vuln:highkev"] > risk["vuln:crit"] > risk["vuln:high"] > 39.0
    assert max(risk.values()) < 100.0


def test_unannotated_path_ranks_below_an_evidence_backed_equal() -> None:
    graph = _graph(freshness="fresh")
    annotated = annotate_attack_path_evidence(_path(50.0), graph)
    raw = _path(90.0)
    raw.source = "agent:z"
    assert attack_path_rank_key(annotated, graph.nodes) < attack_path_rank_key(raw, graph.nodes)


def test_rank_fields_explain_the_order() -> None:
    graph = _graph(freshness="unknown")
    path = annotate_attack_path_evidence(_path(88.0), graph)
    factors = path_rank_fields(path, graph.nodes)["ranking_factors"]
    assert factors["order"] == ["evidence_tier", "is_kev", "severity", "evidence_confidence", "composite_risk", "credential_count"]
    assert factors["evidence_tier"] == 3
    assert factors["is_kev"] is True
    assert factors["severity"] == "high"
    assert factors["severity_scored"] is True
    assert factors["evidence_confidence"] == "structural"
    assert factors["composite_risk"] == 88.0
    assert factors["credential_count"] == 1
    assert factors["reasons"]


class _Store:
    def __init__(self, paths: list[AttackPath], graph: UnifiedGraph) -> None:
        self.paths = paths
        self.graph = graph

    def snapshot_identity(self, **_kwargs):
        return "scan-1", "gen-1"

    def attack_paths(self, **_kwargs):
        return "scan-1", "2026-10-18T00:00:00Z", list(self.paths), len(self.paths)

    def nodes_by_ids(self, *, node_ids: set[str], **_kwargs):
        return [node for node in self.graph.nodes.values() if node.id in node_ids]

    def edges_for_node_ids(self, **_kwargs):
        return list(self.graph.edges)

    def snapshot_stats(self, **_kwargs):
        return {"attack_path_count": len(self.paths)}


def _gate_store() -> _Store:
    graph = _graph(freshness="unknown")
    graph.nodes["pkg:pypi:pillow@9.0.0"].attributes.update({"version": "9.0.0", "native_id": "pkg:pypi/pillow@9.0.0"})
    path = annotate_attack_path_evidence(_path(60.0), graph)
    return _Store([path], graph)


async def _gate(candidate: str, store: _Store) -> dict:
    raw = await deploy_decision_impl(
        candidate=candidate, tenant_id="tenant-a", _get_graph_store=lambda: store, _truncate_response=lambda v: v
    )
    return json.loads(raw)


@pytest.mark.asyncio
async def test_kev_path_from_agent_with_credentials_blocks_below_risk_threshold() -> None:
    payload = await _gate("pillow", _gate_store())
    assert payload["maxRisk"] == 60.0
    assert payload["decision"] == "block"
    assert payload["matchedPathCount"] == 1
    assert any("KEV" in reason for reason in payload["reasons"])


@pytest.mark.asyncio
@pytest.mark.parametrize("candidate", ["pillow", "PILLOW", "pillow@9.0.0", "pkg:pypi/pillow", "pkg:pypi/pillow@9.0.0", "CVE-2023-4863"])
async def test_candidate_matches_exact_identifiers(candidate: str) -> None:
    payload = await _gate(candidate, _gate_store())
    assert payload["matchedPathCount"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("candidate", ["pill", "low", "CVE-2023", "image", "pillow@9"])
async def test_candidate_substrings_do_not_match(candidate: str) -> None:
    payload = await _gate(candidate, _gate_store())
    assert payload["matchedPathCount"] == 0
    assert payload["decision"] == "not_found"
    assert payload["evidenceStatus"] == "not_evaluated"
    assert payload["maxRisk"] is None


@pytest.mark.asyncio
async def test_unlikely_kev_path_does_not_block() -> None:
    store = _gate_store()
    store.paths[0].reachability = "unlikely"
    payload = await _gate("pillow", store)
    assert payload["decision"] == "warn"


def test_fusion_does_not_traverse_trace_order() -> None:
    from agent_bom.graph.attack_path_fusion import _TRAVERSABLE_RELS

    assert RelationshipType.TRACE_STEP not in _TRAVERSABLE_RELS


def test_untyped_relationship_is_reported_as_a_gap() -> None:
    from agent_bom.graph.hop_evidence import exposure_hop_evidence

    path = AttackPath(source="a", target="b", hops=["a", "b"], edges=["trace_step:a:b"])
    path.hop_evidence = [{"source_node_id": "a", "target_node_id": "b", "relationship": "trace_step:a:b", "complete": True}]
    [receipt] = exposure_hop_evidence(path)
    assert receipt["complete"] is False
    assert receipt["reason_codes"] == ["unsupported_hop_relationship"]


@pytest.fixture(scope="module")
def seeded_demo(tmp_path_factory):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT, seed_showcase_graph_if_empty

    store = SQLiteGraphStore(db_path=tmp_path_factory.mktemp("demo") / "graph.db")
    assert seed_showcase_graph_if_empty(store, tenant_id=SHOWCASE_TENANT)
    _scan, _created, paths, total = store.attack_paths(tenant_id=SHOWCASE_TENANT, scan_id="", offset=0, limit=100_000)
    assert len(paths) == total > 0
    return store, paths


def test_demo_paths_carry_recorded_analysis_and_typed_relationships(seeded_demo) -> None:
    _store, paths = seeded_demo
    relationship_values = {item.value for item in RelationshipType}
    assert {path.analysis.get("status") for path in paths} == {"complete"}
    assert all(edge in relationship_values for path in paths for edge in path.edges)
    receipts = [receipt for path in paths for receipt in path.hop_evidence]
    assert receipts and not any(receipt["truncated"] for receipt in receipts)
    assert not any("unsupported_hop_relationship" in receipt["reason_codes"] for receipt in receipts)


def test_demo_trace_chains_are_unscored_context_ranked_below_scored_findings(seeded_demo) -> None:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT
    from agent_bom.graph.attack_path_queue import AttackPathFilters, ranked_snapshot_path_page

    store, paths = seeded_demo
    trace = [path for path in paths if RelationshipType.TRACE_STEP.value in path.edges]
    assert trace
    assert all(path.reachability == "unknown" and "trace_order_correlation" in path.reachability_basis for path in trace)
    page = ranked_snapshot_path_page(store, scan_id="", tenant_id=SHOWCASE_TENANT, offset=0, limit=100_000, filters=AttackPathFilters())
    assert page is not None
    hop_ids = {hop for path in page.paths for hop in path.hops}
    nodes = {node.id: node for node in store.nodes_by_ids(tenant_id=SHOWCASE_TENANT, scan_id=page.scan_id, node_ids=hop_ids)}
    factors = [path_rank_fields(path, nodes)["ranking_factors"] for path in page.paths]
    scored = [index for index, item in enumerate(factors) if item["severity_scored"]]
    unscored = [index for index, item in enumerate(factors) if not item["severity_scored"]]
    assert scored and unscored and max(scored) < min(unscored)
    top = factors[:10]
    # Without the cap the head of the queue no longer ties at one value.
    assert len({item["composite_risk"] for item in top}) > 1
    assert top[0]["is_kev"] is True


@pytest.mark.asyncio
async def test_demo_deploy_gate_blocks_kev_pillow(seeded_demo) -> None:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store, _paths = seeded_demo

    async def gate(candidate: str) -> str:
        raw = await deploy_decision_impl(
            candidate=candidate, tenant_id=SHOWCASE_TENANT, _get_graph_store=lambda: store, _truncate_response=lambda v: v
        )
        return str(json.loads(raw)["decision"])

    assert await gate("pillow") == "block"
    assert await gate("CVE-2023-4863") == "block"
    assert await gate("no-such-package") == "not_found"
