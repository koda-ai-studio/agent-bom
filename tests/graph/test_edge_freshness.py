"""Edge freshness receipts: observed in this snapshot, carried past the window, or no basis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agent_bom import config
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_freshness import stamp_edge_freshness
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType

_SNAPSHOT = datetime(2026, 9, 24, 2, 0, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-1", tenant_id="t", created_at=_iso(_SNAPSHOT))
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="s"))
    graph.add_node(UnifiedNode(id="tool:t", entity_type=EntityType.TOOL, label="t"))
    return graph


def _edge(source: str, target: str, relationship: RelationshipType, *, last_seen: datetime, **evidence: object) -> UnifiedEdge:
    return UnifiedEdge(
        source=source,
        target=target,
        relationship=relationship,
        last_seen=_iso(last_seen),
        evidence={"source": "fixture", **evidence},
    )


def test_freshness_window_is_a_documented_config_value() -> None:
    assert config.GRAPH_EDGE_FRESHNESS_HOURS == 168


def test_edge_collected_in_this_snapshot_is_fresh() -> None:
    graph = _graph()
    graph.add_edge(_edge("agent:a", "server:s", RelationshipType.USES, last_seen=_SNAPSHOT + timedelta(minutes=3)))

    counts = stamp_edge_freshness(graph, window_hours=168)

    (edge,) = graph.edges
    assert edge.evidence["freshness"] == "fresh"
    assert counts == {"fresh": 1, "stale": 0, "unknown": 0, "recorded": 0}


def test_edge_observed_before_the_window_is_stale_even_with_a_recent_last_seen() -> None:
    graph = _graph()
    old = _SNAPSHOT - timedelta(days=30)
    graph.add_edge(_edge("agent:a", "tool:t", RelationshipType.INVOKED, last_seen=_SNAPSHOT, observed_at=_iso(old)))
    graph.add_edge(_edge("server:s", "tool:t", RelationshipType.PROVIDES_TOOL, last_seen=old))

    counts = stamp_edge_freshness(graph, window_hours=168)

    assert {edge.relationship: edge.evidence["freshness"] for edge in graph.edges} == {
        RelationshipType.INVOKED: "stale",
        RelationshipType.PROVIDES_TOOL: "stale",
    }
    assert counts["stale"] == 2


def test_edge_without_a_parseable_observation_time_stays_unstamped() -> None:
    graph = _graph()
    edge = _edge("agent:a", "server:s", RelationshipType.USES, last_seen=_SNAPSHOT)
    graph.add_edge(edge)
    edge.last_seen = "not-a-timestamp"

    counts = stamp_edge_freshness(graph, window_hours=168)

    assert "freshness" not in edge.evidence
    assert counts["unknown"] == 1


def test_recorded_freshness_is_never_overwritten() -> None:
    graph = _graph()
    graph.add_edge(_edge("agent:a", "server:s", RelationshipType.USES, last_seen=_SNAPSHOT, freshness="stale_allowed"))
    correlated = _edge("server:s", "tool:t", RelationshipType.PROVIDES_TOOL, last_seen=_SNAPSHOT)
    correlated.provenance = {"correlation": {"freshness": "stale_allowed"}}
    graph.add_edge(correlated)

    counts = stamp_edge_freshness(graph, window_hours=168)

    edges = {edge.relationship: edge for edge in graph.edges}
    assert edges[RelationshipType.USES].evidence["freshness"] == "stale_allowed"
    assert "freshness" not in edges[RelationshipType.PROVIDES_TOOL].evidence
    assert counts["recorded"] == 2


def _path_graph(*, tool_hop_seen: datetime) -> tuple[UnifiedGraph, AttackPath]:
    graph = _graph()
    graph.add_edge(_edge("agent:a", "server:s", RelationshipType.USES, last_seen=_SNAPSHOT))
    graph.add_edge(_edge("server:s", "tool:t", RelationshipType.PROVIDES_TOOL, last_seen=tool_hop_seen))
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    stamp_edge_freshness(graph, window_hours=168)
    path = AttackPath(
        source="agent:a",
        target="tool:t",
        hops=["agent:a", "server:s", "tool:t"],
        edges=[RelationshipType.USES.value, RelationshipType.PROVIDES_TOOL.value],
    )
    return graph, path


def test_fresh_directed_provenance_backed_path_is_confirmed() -> None:
    graph, path = _path_graph(tool_hop_seen=_SNAPSHOT)

    annotate_attack_path_evidence(path, graph)

    assert [receipt["freshness"] for receipt in path.hop_evidence] == ["fresh", "fresh"]
    assert path.reachability == "confirmed"
    assert "directed_provenance_backed_hops" in path.reachability_basis


def test_path_with_a_stale_hop_stays_unknown_with_a_stale_reason() -> None:
    graph, path = _path_graph(tool_hop_seen=_SNAPSHOT - timedelta(days=30))

    annotate_attack_path_evidence(path, graph)

    assert path.reachability == "unknown"
    assert "stale_hop_evidence" in path.reachability_basis
    assert "stale_evidence" in path.hop_evidence[1]["reason_codes"]


def _report() -> dict[str, object]:
    return {
        "agents": [
            {
                "name": "agent",
                "type": "custom",
                "mcp_servers": [{"name": "srv", "command": "npx", "tools": [{"name": "read_file"}]}],
            }
        ]
    }


def test_scan_build_stamps_every_collected_edge_fresh() -> None:
    graph = build_unified_graph_from_report(_report(), scan_id="scan-1", tenant_id="t")

    assert graph.edges
    assert {edge.evidence.get("freshness") for edge in graph.edges} == {"fresh"}


def test_store_backed_scan_build_persists_freshness() -> None:
    with open_store_backed_unified_graph(scan_id="scan-1", tenant_id="t", backend="sqlite") as graph:
        build_unified_graph_from_report(_report(), scan_id="scan-1", tenant_id="t", container=graph)
        edges = list(graph.edges)

    assert edges
    assert {edge.evidence.get("freshness") for edge in edges} == {"fresh"}


def test_fresh_hops_do_not_promote_a_structural_topology_only_verdict() -> None:
    graph, path = _path_graph(tool_hop_seen=_SNAPSHOT)
    path.reachability_basis = ["structural_topology_only"]

    annotate_attack_path_evidence(path, graph)

    assert all(receipt["complete"] for receipt in path.hop_evidence)
    assert path.reachability == "unknown"
    assert "directed_provenance_backed_hops" not in path.reachability_basis


def _finding_path_graph(applicability: dict[str, object] | None) -> tuple[UnifiedGraph, AttackPath]:
    graph = _graph()
    graph.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="p"))
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="high"))
    graph.add_edge(_edge("server:s", "pkg:p", RelationshipType.DEPENDS_ON, last_seen=_SNAPSHOT))
    evidence = {"applicability": applicability} if applicability else {}
    graph.add_edge(_edge("pkg:p", "vuln:CVE-1", RelationshipType.VULNERABLE_TO, last_seen=_SNAPSHOT, **evidence))
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    stamp_edge_freshness(graph, window_hours=168)
    path = AttackPath(source="server:s", target="vuln:CVE-1", hops=["server:s", "pkg:p", "vuln:CVE-1"],
                      edges=[RelationshipType.DEPENDS_ON.value, RelationshipType.VULNERABLE_TO.value])
    return graph, path


def test_fresh_advisory_match_without_applicability_does_not_confirm_the_path() -> None:
    # A fresh package -> CVE match proves the version is affected, not that the code is reachable.
    graph, path = _finding_path_graph(None)

    annotate_attack_path_evidence(path, graph)

    assert path.reachability != "confirmed"
    assert "applicability_unverified" in path.hop_evidence[1]["reason_codes"]


def test_fresh_advisory_match_with_likely_applicability_can_confirm() -> None:
    graph, path = _finding_path_graph({"verdict": "likely", "basis": ["package_reachable"]})

    annotate_attack_path_evidence(path, graph)

    assert path.reachability == "confirmed"
