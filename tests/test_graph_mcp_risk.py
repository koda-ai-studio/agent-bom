"""Capability assessments remain bounded to recorded MCP assets and relationships."""

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.mcp_risk import apply_mcp_risk
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_mcp_capability_scores_use_existing_analyzer_and_provenance():
    from agent_bom.models import MCPTool
    from agent_bom.risk_analyzer import score_server_risk, score_tool_risk

    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    tool = UnifiedNode(id="tool", entity_type=EntityType.TOOL, label="execute_command", attributes={"declared_capabilities": ["execute"]})
    server = UnifiedNode(id="server", entity_type=EntityType.SERVER, label="MCP")
    empty = UnifiedNode(id="empty", entity_type=EntityType.SERVER, label="Unknown")
    cred = UnifiedNode(id="cred", entity_type=EntityType.CREDENTIAL, label="AWS_ROLE_SESSION")
    for node in (tool, server, empty, cred):
        graph.add_node(node)
    for target, relationship in (("tool", RelationshipType.PROVIDES_TOOL), ("cred", RelationshipType.EXPOSES_CRED)):
        graph.add_edge(UnifiedEdge(source="server", target=target, relationship=relationship, evidence={"tier": "static_scan"}))
    original_edges = graph.to_dict()["edges"]
    apply_mcp_risk(graph)
    model = MCPTool(name="execute_command", description="", declared_capabilities=["execute"])
    assert tool.risk_score == score_tool_risk(model).risk_score
    assert server.risk_score == round(score_server_risk([model], credentials=["AWS_ROLE_SESSION"]).risk_score, 2)
    assert server.risk_assessment["status"] == "assessed"
    assert "capability" in server.risk_assessment["basis"]
    assert empty.risk_assessment["status"] == "not_assessed"
    assert graph.to_dict()["edges"] == original_edges
    first = graph.to_dict()
    apply_mcp_risk(graph)
    assert graph.to_dict() == first


def test_modeled_membership_does_not_claim_recorded_server_capability():
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    server = UnifiedNode(id="s", entity_type=EntityType.SERVER, label="s")
    tool = UnifiedNode(id="t", entity_type=EntityType.TOOL, label="execute_command")
    graph.add_node(server)
    graph.add_node(tool)
    graph.add_edge(
        UnifiedEdge(source="s", target="t", relationship=RelationshipType.PROVIDES_TOOL, evidence={"tier": "modeled_infrastructure"})
    )
    apply_mcp_risk(graph)
    assert server.risk_assessment["status"] == "not_assessed"
    assert tool.risk_assessment["status"] == "assessed"
    assert "inferred" in tool.attributes["capability_risk"]["basis"]


def test_scan_pipeline_exposes_assessment_and_preserves_stronger_scored_evidence():
    from agent_bom.graph.builder import build_unified_graph_from_report

    graph = build_unified_graph_from_report(
        {
            "scan_id": "mcp-score",
            "agents": [
                {
                    "name": "test-agent",
                    "type": "custom",
                    "mcp_servers": [
                        {
                            "name": "shell",
                            "surface": "mcp-server",
                            "command": "local",
                            "transport": "stdio",
                            "tools": [{"name": "execute_command", "declared_capabilities": ["execute"]}],
                        }
                    ],
                }
            ],
        }
    )
    server = next(graph.iter_nodes_by_type(EntityType.SERVER))
    tool = next(graph.iter_nodes_by_type(EntityType.TOOL))
    assert server.risk_assessment["status"] == tool.risk_assessment["status"] == "assessed"
    server.risk_score = 9.7
    server.mark_risk_assessed(basis="recorded_vulnerability", scope="dependency")
    apply_mcp_risk(graph)
    assert server.risk_score == 9.7
    assert server.risk_assessment["basis"] == "recorded_vulnerability"
    assert server.attributes["capability_risk"]["score"] < server.risk_score
