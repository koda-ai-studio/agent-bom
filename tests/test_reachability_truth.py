"""One reachability verdict drives labels, ranking, paths, and correlations."""

from __future__ import annotations

from agent_bom.evidence.semantics import ReachabilityVerdict
from agent_bom.graph.reachability_truth import assess_reachability
from agent_bom.models import BlastRadius, MCPTool, Package, Severity, Vulnerability


def _blast(*, severity: Severity, graph: bool | None = None, symbol: str | None = None) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-9001",
            summary="unrated actively exploited advisory",
            severity=severity,
            is_kev=True,
            epss_score=0.95,
        ),
        package=Package(name="edge-case", version="1.0.0", ecosystem="pypi", is_direct=True),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=["PROD_TOKEN"],
        exposed_tools=[MCPTool(name="run_shell", description="execute a shell command")],
        graph_reachable=graph,
        symbol_reachability=symbol,
    )


def test_proven_unreachable_overrides_exposure_heuristics_everywhere() -> None:
    blast = _blast(severity=Severity.HIGH, graph=False, symbol="unreachable")

    assert blast.reachability == "unlikely"
    blast.calculate_risk_score()
    assert blast.risk_score < _blast(severity=Severity.HIGH, graph=True, symbol="function_reachable").calculate_risk_score()


def test_modeled_graph_path_alone_is_likely_not_confirmed() -> None:
    assert _blast(severity=Severity.HIGH, graph=True).reachability == "likely"
    assessment = assess_reachability(graph_reachable=True)
    assert assessment.verdict is ReachabilityVerdict.LIKELY
    assert assessment.basis == ("graph_path",)


def test_function_level_evidence_is_required_for_confirmed() -> None:
    assert _blast(severity=Severity.HIGH, symbol="function_reachable").reachability == "confirmed"
    assessment = assess_reachability(graph_reachable=True, symbol_reachability="function_reachable")
    assert assessment.verdict is ReachabilityVerdict.CONFIRMED
    assert assessment.basis == ("function_reachable", "graph_path")


def test_graph_path_outranks_unknown_symbol_analysis() -> None:
    assessment = assess_reachability(graph_reachable=True, symbol_reachability="unknown")
    assert assessment.verdict is ReachabilityVerdict.LIKELY


def test_graph_path_keeps_its_risk_boost_after_the_verdict_downgrade() -> None:
    reachable = _blast(severity=Severity.HIGH, graph=True).calculate_risk_score()
    unassessed = _blast(severity=Severity.HIGH).calculate_risk_score()
    assert reachable > unassessed


def test_persisted_confirmed_without_function_or_runtime_basis_is_downgraded() -> None:
    from agent_bom.graph.reachability_truth import node_reachability

    modeled = node_reachability({"reachability": "confirmed", "reachability_basis": ["graph_path"], "graph_reachable": True})
    assert modeled.verdict is ReachabilityVerdict.LIKELY
    assert modeled.basis == ("graph_path",)
    proven = node_reachability({"reachability": "confirmed", "reachability_basis": ["function_reachable"]})
    assert proven.verdict is ReachabilityVerdict.CONFIRMED
    observed = node_reachability({"reachability": "confirmed", "reachability_basis": ["runtime_observed"]})
    assert observed.verdict is ReachabilityVerdict.CONFIRMED


def test_unrated_active_exploitation_never_ranks_below_equivalent_low() -> None:
    unknown = _blast(severity=Severity.UNKNOWN)
    none = _blast(severity=Severity.NONE)
    low = _blast(severity=Severity.LOW)

    assert unknown.calculate_risk_score() >= low.calculate_risk_score()
    assert none.calculate_risk_score() >= low.calculate_risk_score()
