"""Credential reach findings retain identity, severity and exact graph paths."""

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.scan_findings import attach_graph_derived_findings
from agent_bom.models import AIBOMReport
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _scan():
    inventory = {
        "agents": [
            {
                "name": name,
                "type": "cursor",
                "config_path": f"/{name}/mcp.json",
                "mcp_servers": [{"name": f"files-{name}", "command": "node", "args": ["server.js"], "credential_env_vars": ["API_TOKEN"]}],
            }
            for name in ("workspace-a", "workspace-b")
        ]
    }
    graph = build_unified_graph_from_report(inventory, scan_id="scan-a", tenant_id="tenant-a")
    report = AIBOMReport(agents=[])
    attach_graph_derived_findings(report, graph)
    findings = [f for f in report.to_findings() if f.evidence.get("rule_id") == "AGENT_REACHES_PRIVILEGED"]
    return inventory, graph, findings


def test_credential_findings_are_linked_nodes_with_scope_severity():
    _, graph, findings = _scan()
    assert len(findings) == 2
    assert all(f.finding_node_id in graph.nodes for f in findings)
    for finding in findings:
        node = graph.nodes[finding.finding_node_id]
        assert node.severity == finding.severity == "high"
        assert node.attributes["finding_id"] == finding.id
        assert node.attributes["remediation"] == finding.remediation_guidance
        scoped = next(row for row in rollup_view(graph)["top_level"] if row["id"] == finding.node_id)
        assert scoped["aggregate"]["severity_counts"]["high"] == 1


def test_rebuilt_snapshot_preserves_findings_and_paths_without_cross_agent_links():
    inventory, _, findings = _scan()
    payload = {**inventory, "findings": [f.to_dict() for f in findings]}
    graph = build_unified_graph_from_report(payload, scan_id="scan-a", tenant_id="tenant-a")
    paths = [p for p in _derived_attack_paths(graph) if p.finding_ids]
    assert len(paths) == 2
    for finding in findings:
        matching = [p for p in paths if finding.id in p.finding_ids]
        assert len(matching) == 1
        path = matching[0]
        assert path.source == finding.node_id
        assert path.target == finding.finding_node_id
        assert len(path.hops) == 4  # agent, server, credential, assessment
        assert path.edges == ["uses", "exposes_cred", "vulnerable_to"]
        assert path.reachability == "unknown"
        assert "successful use" in path.summary
    assert graph.stats()["severity_counts"] == {"high": 2}


def test_projection_replay_does_not_duplicate_or_escalate_findings():
    from agent_bom.graph.credential_findings import project_credential_findings

    _, graph, findings = _scan()
    before = (len(graph.nodes), len(graph.edges))
    project_credential_findings(graph, [f.to_dict() for f in findings] * 2)
    assert (len(graph.nodes), len(graph.edges)) == before
    report = AIBOMReport(agents=[])
    attach_graph_derived_findings(report, graph)
    replay = [f for f in report.to_findings() if f.evidence.get("rule_id") == "AGENT_REACHES_PRIVILEGED"]
    assert {(f.id, f.severity, f.finding_node_id) for f in replay} == {(f.id, f.severity, f.finding_node_id) for f in findings}


def test_missing_owner_or_wrong_source_cannot_create_graph_links():
    from agent_bom.graph.credential_findings import project_credential_findings

    inventory, _, findings = _scan()
    graph = build_unified_graph_from_report(inventory)
    before = (len(graph.nodes), len(graph.edges))
    row = findings[0].to_dict()
    unresolvable = {**row, "node_id": "agent:absent", "asset": {**row["asset"], "identifier": "absent"}}
    project_credential_findings(graph, [None, unresolvable, {**row, "source": "MCP_SCAN"}])
    assert (len(graph.nodes), len(graph.edges)) == before


def test_foreign_scoped_owner_rebinds_through_the_agent_identity():
    from agent_bom.graph.credential_findings import project_credential_findings

    inventory, _, findings = _scan()
    graph = build_unified_graph_from_report(inventory)
    row = findings[0].to_dict()
    owner = row["node_id"]
    project_credential_findings(graph, [{**row, "node_id": "agent:cfg-elsewhere:pushed"}])
    finding_node = f"misconfig:graph_analysis:{row['id']}"
    assert finding_node in graph.nodes
    assert any(edge.source == owner and edge.target == finding_node for edge in graph.edges)


def test_persisted_api_returns_high_paths_and_scoped_counts(api):  # noqa: F811
    client, store, headers = api
    _, graph, findings = _scan()
    store.save_graph(graph)
    response = client.get("/v1/graph/attack-paths", params={"scan_id": graph.scan_id}, headers=headers["tenant-a"])
    assert response.status_code == 200, response.text
    payload = response.json()
    assert {f.id for f in findings} <= {fid for path in payload["attack_paths"] for fid in path["finding_ids"]}
    rollup = client.get("/v1/graph/rollup", params={"scan_id": graph.scan_id}, headers=headers["tenant-a"])
    assert rollup.status_code == 200, rollup.text
    scopes = {row["id"]: row for row in rollup.json()["top_level"]}
    for finding in findings:
        assert scopes[finding.node_id]["aggregate"]["severity_counts"]["high"] == 1
    denied = client.get("/v1/graph/attack-paths", params={"scan_id": graph.scan_id}, headers=headers["tenant-b"])
    assert all(f.id not in denied.text for f in findings)


def test_export_keeps_finding_node_coordinate_without_allowing_embedded_secrets():
    from agent_bom.security import sanitize_sensitive_payload

    coordinate = "misconfig:graph_analysis:f319a10a-aacb-5c6f-b718-9e972987a7d5"
    assert sanitize_sensitive_payload({"finding_node_id": coordinate})["finding_node_id"] == coordinate
    secret = "misconfig:graph_analysis:ghp_" + "x" * 36
    assert secret not in str(sanitize_sensitive_payload({"finding_node_id": secret}))


def test_paths_do_not_walk_nontraversable_credential_edges():
    from agent_bom.graph.credential_findings import credential_finding_paths
    from agent_bom.graph.types import RelationshipType

    _, graph, _ = _scan()
    for edge in graph.edges:
        if edge.relationship == RelationshipType.EXPOSES_CRED:
            edge.traversable = False
    assert credential_finding_paths(graph) == []


def test_shared_topology_never_assigns_another_agents_finding_to_a_path():
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.credential_findings import credential_finding_paths
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import RelationshipType

    _, graph, findings = _scan()
    graph.add_edge(
        UnifiedEdge(
            source=findings[0].node_id, target=findings[1].node_id, relationship=RelationshipType.SHARES_SERVER, direction="bidirectional"
        )
    )
    restored = UnifiedGraph.from_dict(graph.to_dict())
    owners = {f.id: f.node_id for f in findings}
    paths = credential_finding_paths(restored)
    assert len(paths) == 2
    assert all(owners[fid] == path.source for path in paths for fid in path.finding_ids)


def test_shared_server_link_before_evaluation_does_not_transfer_credentials():
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import EntityType, RelationshipType

    inventory, _, _ = _scan()
    graph = build_unified_graph_from_report(inventory)
    agents = list(graph.nodes_by_type(EntityType.AGENT))
    graph.add_edge(
        UnifiedEdge(source=agents[0].id, target=agents[1].id, relationship=RelationshipType.SHARES_SERVER, direction="bidirectional")
    )
    report = AIBOMReport(agents=[])
    attach_graph_derived_findings(report, graph)
    findings = [f for f in report.to_findings() if f.evidence.get("rule_id") == "AGENT_REACHES_PRIVILEGED"]
    assert len(findings) == 2
    for finding in findings:
        assert len(finding.evidence["node_ids"]) == 2  # owner plus its own credential
    paths = [p for p in _derived_attack_paths(graph) if p.finding_ids]
    assert len(paths) == 2
    assert all("shares_server" not in p.edges for p in paths)


def test_projection_rejects_foreign_credentials_in_stale_findings():
    from agent_bom.graph.credential_findings import project_credential_findings

    inventory, _, findings = _scan()
    graph = build_unified_graph_from_report(inventory)
    own_credentials = list(findings[0].evidence["node_ids"][1:])
    row = findings[0].to_dict()
    row["evidence"]["node_ids"] += findings[1].evidence["node_ids"]
    project_credential_findings(graph, [row])
    node = graph.nodes[findings[0].finding_node_id]
    assert node.attributes["credential_node_ids"] == own_credentials


def test_credential_traversal_agent_budget_is_reported(monkeypatch):
    from agent_bom.graph import credential_reach
    from agent_bom.graph.types import EntityType

    _, graph, _ = _scan()
    monkeypatch.setattr(credential_reach, "MAX_AGENT_EDGES", 1)
    routes = credential_reach.credential_routes(graph, (a.id for a in graph.nodes_by_type(EntityType.AGENT)), analyzer="test_budget")
    status = graph.analysis_status["test_budget"]
    assert status.status.value == "limited"
    assert status.reason_codes == ("agent_budget",)
    assert "edges" not in status.limits and "results" not in status.limits
    assert status.observed["agents"] == 2
    assert sum(len(credentials) for credentials in routes.values()) == 0


def test_shared_credential_is_terminal_and_associations_are_indexed(monkeypatch):
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.credential_findings import credential_finding_paths
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="cred:shared", label="TOKEN", entity_type=EntityType.CREDENTIAL))
    for i in range(100):
        owner, fid = f"agent:{i}", f"finding:{i}"
        graph.add_node(UnifiedNode(id=owner, label=owner, entity_type=EntityType.AGENT))
        graph.add_node(
            UnifiedNode(
                id=fid,
                label=fid,
                entity_type=EntityType.MISCONFIGURATION,
                attributes={
                    "finding_source": "GRAPH_ANALYSIS",
                    "rule_id": "AGENT_REACHES_PRIVILEGED",
                    "owner_node_id": owner,
                    "credential_node_ids": ["cred:shared"],
                    "finding_id": fid,
                },
            )
        )
        graph.add_edge(UnifiedEdge(source=owner, target="cred:shared", relationship=RelationshipType.EXPOSES_CRED))
        graph.add_edge(UnifiedEdge(source="cred:shared", target=fid, relationship=RelationshipType.VULNERABLE_TO))

    class NoAdjacency(dict):
        def get(self, *args):
            raise AssertionError("must use one edge index, not rescan shared credential fan-out")

    original_adjacency = graph.adjacency
    graph.adjacency = NoAdjacency()
    paths = credential_finding_paths(graph)
    assert len(paths) == 100
    assert graph.analysis_status["credential_finding_paths"].observed["edges"] == 100
    assert all(p.edges[-1] == "vulnerable_to" for p in paths)
    graph.adjacency = original_adjacency
    from agent_bom.graph import path_derivation

    calls = 0
    original = path_derivation._rel_value

    def count(edge):
        nonlocal calls
        calls += 1
        return original(edge)

    monkeypatch.setattr(path_derivation, "_rel_value", count)
    assert len(_derived_attack_paths(graph)) == 100
    assert calls <= len(graph.edges) * 3


def test_credential_budget_survives_path_evidence_annotation(monkeypatch):
    from agent_bom.graph import credential_reach
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.credential_findings import project_credential_findings
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.toxic_findings import build_toxic_combination_findings_data
    from agent_bom.graph.types import EntityType, RelationshipType

    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="agent:a", label="a", entity_type=EntityType.AGENT))
    for i in (1, 2):
        graph.add_node(UnifiedNode(id=f"server:{i}", label=f"s{i}", entity_type=EntityType.SERVER))
        graph.add_node(UnifiedNode(id=f"cred:{i}", label=f"c{i}", entity_type=EntityType.CREDENTIAL))
        graph.add_edge(UnifiedEdge(source="agent:a", target=f"server:{i}", relationship=RelationshipType.USES))
        graph.add_edge(UnifiedEdge(source=f"server:{i}", target=f"cred:{i}", relationship=RelationshipType.EXPOSES_CRED))
    project_credential_findings(graph, build_toxic_combination_findings_data(graph))
    monkeypatch.setattr(credential_reach, "MAX_AGENT_EDGES", 3)
    paths = [p for p in _derived_attack_paths(graph) if p.finding_ids]
    assert [p.hops[-2] for p in paths] == ["cred:1"]
    assert paths[0].analysis["status"] == "limited"
    assert paths[0].analysis["reason_codes"] == ["agent_budget"]


def test_path_budget_keeps_the_agent_budget_reason(monkeypatch):
    from agent_bom.graph import credential_findings, credential_reach
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.toxic_findings import build_toxic_combination_findings_data
    from agent_bom.graph.types import EntityType, RelationshipType

    monkeypatch.setattr(credential_reach, "MAX_AGENT_EDGES", 3)
    monkeypatch.setattr(credential_findings, "MAX_PATHS", 2)
    graph = UnifiedGraph()
    for a in range(3):
        agent, server = f"agent:{a}", f"server:{a}"
        graph.add_node(UnifiedNode(id=agent, label=agent, entity_type=EntityType.AGENT, severity="high"))
        graph.add_node(UnifiedNode(id=server, label=server, entity_type=EntityType.SERVER, severity="high"))
        graph.add_edge(UnifiedEdge(source=agent, target=server, relationship=RelationshipType.USES))
        for c in range(4 if a == 0 else 1):
            cred = f"cred:{a}:{c}"
            graph.add_node(UnifiedNode(id=cred, label=cred, entity_type=EntityType.CREDENTIAL, severity="high"))
            graph.add_edge(UnifiedEdge(source=server, target=cred, relationship=RelationshipType.EXPOSES_CRED))
    credential_findings.project_credential_findings(graph, build_toxic_combination_findings_data(graph))
    paths = credential_findings.credential_finding_paths(graph)
    status = graph.analysis_status["credential_finding_paths"]
    assert len(paths) == 2
    assert status.status.value == "limited"
    assert status.reason_codes == ("agent_budget", "path_budget")
    assert all(path.analysis["reason_codes"] == ["agent_budget", "path_budget"] for path in paths)
