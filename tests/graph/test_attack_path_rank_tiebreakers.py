"""The attack-path queue must discriminate paths that tie on stored risk.

On the demo estate 1,026 trace-correlation paths share ``composite_risk`` 80.0
and 251 share 0.0, all in evidence tier 0. With nothing after
``credential_count`` in the rank key, those groups fell back to lexical
``source``/``target`` order: alphabetical, not risk. The tie-breakers below are
read from evidence already on the path (EPSS, internet exposure, environment
criticality, hop count) and never change ``composite_risk``.
"""

from __future__ import annotations

import random

from agent_bom.graph import AttackPath, EntityType, UnifiedNode
from agent_bom.graph.attack_path_queue_rank import (
    RANKING_ORDER,
    attack_path_rank_key,
    path_ranking_factors,
    rank_attack_paths,
    ranking_node_ids,
)


def _node(node_id: str, kind: EntityType = EntityType.CLOUD_RESOURCE, **attrs: object) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=kind, label=node_id, attributes=dict(attrs))


def _path(*hops: str, risk: float = 80.0) -> AttackPath:
    return AttackPath(source=hops[0], target=hops[-1], hops=list(hops), edges=["trace_step"] * (len(hops) - 1), composite_risk=risk)


def _first(paths: list[AttackPath], nodes: dict[str, UnifiedNode]) -> AttackPath:
    return rank_attack_paths(paths, nodes)[0]


def test_internet_exposed_path_outranks_internal_tie() -> None:
    nodes = {n.id: n for n in [_node("a:internal"), _node("z:exposed", internet_exposed=True), _node("t:1"), _node("t:2")]}
    exposed = _path("z:exposed", "t:2")
    assert _first([_path("a:internal", "t:1"), exposed], nodes) is exposed


def test_production_path_outranks_development_tie() -> None:
    nodes = {n.id: n for n in [_node("a:dev", environment="development"), _node("z:prod", environment="production"), _node("t:1")]}
    prod = _path("z:prod", "t:1")
    assert _first([_path("a:dev", "t:1"), prod], nodes) is prod


def test_higher_epss_finding_outranks_tie() -> None:
    low = _node("vuln:CVE-A", EntityType.VULNERABILITY, epss_score=0.01)
    high = _node("vuln:CVE-Z", EntityType.VULNERABILITY, epss_score=0.92)
    for n in (low, high):
        n.severity = "high"
    nodes = {n.id: n for n in [_node("s:1"), low, high]}
    likely = _path("s:1", "vuln:CVE-Z", risk=60.0)
    likely.vuln_ids = ["CVE-Z"]
    other = _path("s:1", "vuln:CVE-A", risk=60.0)
    other.vuln_ids = ["CVE-A"]
    assert _first([other, likely], nodes) is likely


def test_shorter_path_outranks_longer_tie() -> None:
    nodes = {n.id: n for n in [_node("a:1"), _node("m:1"), _node("t:1")]}
    direct = _path("a:1", "t:1")
    assert _first([_path("a:1", "m:1", "t:1"), direct], nodes) is direct


def test_tie_breakers_never_override_composite_risk_or_change_it() -> None:
    nodes = {n.id: n for n in [_node("a:internal"), _node("z:exposed", internet_exposed=True, environment="production"), _node("t:1")]}
    riskier = _path("a:internal", "t:1", risk=81.0)
    exposed = _path("z:exposed", "t:1", risk=80.0)
    ranked = rank_attack_paths([exposed, riskier], nodes)
    assert ranked[0] is riskier
    assert (riskier.composite_risk, exposed.composite_risk) == (81.0, 80.0)


def test_order_is_stable_under_input_permutation() -> None:
    nodes: dict[str, UnifiedNode] = {}
    paths = []
    for i in range(40):
        src = _node(f"s:{i:02d}", internet_exposed=i % 3 == 0, environment=("production", "staging", "dev")[i % 3])
        nodes[src.id] = src
        hops = [src.id] + [f"m:{i}:{j}" for j in range(i % 4)] + ["t:0"]
        for hop in hops[1:]:
            nodes.setdefault(hop, _node(hop))
        paths.append(_path(*hops))
    expected = [id(p) for p in rank_attack_paths(paths, nodes)]
    for seed in range(5):
        shuffled = paths[:]
        random.Random(seed).shuffle(shuffled)
        assert [id(p) for p in rank_attack_paths(shuffled, nodes)] == expected
    groups = {attack_path_rank_key(p, nodes)[:-3] for p in paths}
    assert len(groups) >= 10, "tie-breakers should split a 40-path tie into many groups"


def test_factors_are_reported_in_rank_order() -> None:
    nodes = {n.id: n for n in [_node("z:exposed", internet_exposed=True, environment="production"), _node("t:1")]}
    factors = path_ranking_factors(_path("z:exposed", "t:1"), nodes)
    assert factors["order"] == list(RANKING_ORDER)
    assert RANKING_ORDER[-4:] == ("max_epss", "internet_exposed", "environment_weight", "hop_count")
    assert factors["internet_exposed"] is True and factors["environment_weight"] == 1.15 and factors["hop_count"] == 2
    assert any("internet-exposed" in reason for reason in factors["reasons"])


def test_ranking_reads_every_hop_node() -> None:
    """Exposure and environment come from hop nodes, so a persisted-queue read must load them."""
    assert ranking_node_ids([_path("a:1", "t:1")]) == {"a:1", "t:1"}
