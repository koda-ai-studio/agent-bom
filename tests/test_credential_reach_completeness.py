"""Credential-reach finding evaluation is complete, budget-visible and cheap when idle."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType as E
from agent_bom.graph.types import RelationshipType as R

_RULE = "AGENT_REACHES_PRIVILEGED"


def _node(g: UnifiedGraph, node_id: str, kind: E) -> None:
    g.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))


def _edge(g: UnifiedGraph, source: str, target: str, rel: R, **kw) -> None:
    g.add_edge(UnifiedEdge(source=source, target=target, relationship=rel, **kw))


def _per_agent(n: int, creds: int = 1, group: int = 0) -> UnifiedGraph:
    g = UnifiedGraph()
    for i in range(n):
        a, s, t = f"agent:{i}", f"server:{i}", f"tool:{i}"
        _node(g, a, E.AGENT)
        _node(g, s, E.SERVER)
        _node(g, t, E.TOOL)
        _edge(g, a, s, R.USES)
        _edge(g, s, t, R.PROVIDES_TOOL)
        for c in range(creds):
            cid = f"cred:{i}:{c}"
            _node(g, cid, E.CREDENTIAL)
            _edge(g, s, cid, R.EXPOSES_CRED)
            _edge(g, cid, t, R.REACHES_TOOL)
    if group:
        for start in range(0, n, group):
            ids = [f"agent:{i}" for i in range(start, min(n, start + group))]
            for x, a1 in enumerate(ids):
                for a2 in ids[x + 1 :]:
                    _edge(g, a1, a2, R.SHARES_SERVER, direction="bidirectional")
    return g


def _fanout_agent(tools_per_server: int) -> UnifiedGraph:
    g = UnifiedGraph()
    _node(g, "agent:a", E.AGENT)
    for s in range(60):
        sid = f"server:{s}"
        _node(g, sid, E.SERVER)
        _edge(g, "agent:a", sid, R.USES)
        for t in range(tools_per_server):
            tid = f"tool:{s}:{t}"
            _node(g, tid, E.TOOL)
            _edge(g, sid, tid, R.PROVIDES_TOOL)
        _node(g, f"cred:{s}", E.CREDENTIAL)
        _edge(g, sid, f"cred:{s}", R.EXPOSES_CRED)
    return g


def _reach_rows(g: UnifiedGraph) -> list[dict]:
    from agent_bom.graph.toxic_findings import build_toxic_combination_findings_data

    return [r for r in build_toxic_combination_findings_data(g) if r["evidence"].get("rule_id") == _RULE]


def test_finding_evaluation_has_no_global_result_cap():
    # 6,000 agents x 2 credentials = 12,000 credential hits, past the old 10k cap.
    g = _per_agent(6_000, creds=2)
    rows = _reach_rows(g)
    assert len(rows) == 6_000
    assert all(len(r["evidence"]["node_ids"]) == 3 for r in rows)
    assert g.analysis_status["credential_reach"].status.value == "complete"


def test_projection_keeps_every_credential_past_old_cap():
    from agent_bom.graph.credential_findings import project_credential_findings

    g = _per_agent(10_500)
    rows = _reach_rows(g)
    assert len(rows) == 10_500
    project_credential_findings(g, rows)
    projected = [n for n in g.nodes.values() if n.attributes.get("rule_id") == _RULE]
    assert len(projected) == 10_500
    assert all(len(n.attributes["credential_node_ids"]) == 1 for n in projected)


def test_tool_fanout_does_not_truncate_credentials_or_churn_finding_id():
    wide, narrow = _fanout_agent(100), _fanout_agent(1)
    wide_rows, narrow_rows = _reach_rows(wide), _reach_rows(narrow)
    assert len(wide_rows[0]["evidence"]["node_ids"]) - 1 == 60
    assert wide.analysis_status["credential_reach"].status.value == "complete"
    assert wide_rows[0]["id"] == narrow_rows[0]["id"]


def test_agent_budget_exhaustion_is_a_scan_coverage_gap(monkeypatch):
    from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
    from agent_bom.graph import credential_reach
    from agent_bom.graph.scan_findings import attach_graph_derived_findings
    from agent_bom.models import AIBOMReport

    g = _fanout_agent(1)
    monkeypatch.setattr(credential_reach, "MAX_AGENT_EDGES", 3)
    report = AIBOMReport(agents=[])
    attach_graph_derived_findings(report, g)
    warnings = [w for w in report.coverage_warnings if w.get("reason") == "graph_analysis_limited"]
    assert len(warnings) == 1
    assert warnings[0]["ecosystem"] == "graph-credential_reach"
    assert "agent_budget" in warnings[0]["detail"]
    run = effective_scan_run(report)
    assert run.outcome is ScanOutcome.PARTIAL
    assert [i.code for i in run.issues] == ["graph_analysis_coverage_gap"]


def test_complete_evaluation_adds_no_coverage_warning():
    from agent_bom.graph.scan_findings import attach_graph_derived_findings
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(agents=[])
    attach_graph_derived_findings(report, _fanout_agent(5))
    assert report.coverage_warnings == []


class _Untouchable(dict):
    def items(self):
        raise AssertionError("idle requests must not index the whole adjacency")

    def get(self, *args):
        raise AssertionError("idle requests must not index the whole adjacency")


class _UntouchableEdges(list):
    def __iter__(self):
        raise AssertionError("idle requests must not scan every edge")


def test_no_credential_findings_skips_edge_and_hop_indexes():
    from agent_bom.graph.credential_findings import credential_finding_paths
    from agent_bom.graph.path_evidence import with_technique_mappings

    g = _per_agent(50, creds=0, group=10)
    g.adjacency = _Untouchable(g.adjacency)
    g.edges = _UntouchableEdges(g.edges)
    assert credential_finding_paths(g) == []
    assert with_technique_mappings([], g) == []


def test_hop_index_only_covers_path_sources(monkeypatch):
    from agent_bom.graph.path_evidence import with_technique_mappings

    g = _per_agent(200, creds=1)
    path = AttackPath(source="agent:0", target="cred:0:0", hops=["agent:0", "server:0", "cred:0:0"], edges=["uses", "exposes_cred"])
    touched: list[str] = []
    original_get = g.adjacency.get

    class Recording(dict):
        def items(self):
            raise AssertionError("must not index every adjacency list")

        def get(self, key, default=None):
            touched.append(key)
            return original_get(key, default)

    g.adjacency = Recording(g.adjacency)
    with_technique_mappings([path], g)
    assert set(touched) <= {"agent:0", "server:0", "cred:0:0"}


def test_technique_catalog_loads_once_per_batch(monkeypatch):
    from agent_bom import atlas_fetch, mitre_fetch
    from agent_bom.graph.path_evidence import with_technique_mappings

    calls = {"attack": 0, "atlas": 0}
    attack_build, atlas_build = mitre_fetch.build_catalog, atlas_fetch.build_catalog

    def count_attack(*a, **kw):
        calls["attack"] += 1
        return attack_build(*a, **kw)

    def count_atlas(*a, **kw):
        calls["atlas"] += 1
        return atlas_build(*a, **kw)

    monkeypatch.setattr(mitre_fetch, "build_catalog", count_attack)
    monkeypatch.setattr(atlas_fetch, "build_catalog", count_atlas)
    g = _per_agent(30, creds=1)
    paths = [
        AttackPath(
            source=f"agent:{i}",
            target=f"cred:{i}:0",
            hops=[f"agent:{i}", f"server:{i}", f"cred:{i}:0"],
            edges=["uses", "exposes_cred"],
            reachability="confirmed",
        )
        for i in range(30)
    ]
    with_technique_mappings(paths, g)
    assert any(p.technique_mappings for p in paths)
    assert calls["attack"] <= 1
    assert calls["atlas"] <= 1


def test_equal_risk_paths_have_deterministic_order():
    from agent_bom.graph.credential_findings import project_credential_findings
    from agent_bom.graph.path_derivation import _derived_attack_paths

    def build(order):
        g = UnifiedGraph()
        for i in order:
            a, s, c = f"agent:{i}", f"server:{i}", f"cred:{i}"
            _node(g, a, E.AGENT)
            _node(g, s, E.SERVER)
            _node(g, c, E.CREDENTIAL)
            _edge(g, a, s, R.USES)
            _edge(g, s, c, R.EXPOSES_CRED)
        project_credential_findings(g, _reach_rows(g))
        return [p.source for p in _derived_attack_paths(g) if p.finding_ids]

    forward, backward = build(["a", "b", "c"]), build(["c", "b", "a"])
    assert forward == backward == ["agent:a", "agent:b", "agent:c"]
