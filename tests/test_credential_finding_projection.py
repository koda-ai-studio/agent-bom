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
        assert path.edges == ["uses", "exposes_cred", "triggers"]
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
    project_credential_findings(graph, [None, {**row, "node_id": "agent:absent"}, {**row, "source": "MCP_SCAN"}])
    assert (len(graph.nodes), len(graph.edges)) == before


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
