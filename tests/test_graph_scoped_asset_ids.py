"""Asset ids and merges never rest on a display name alone."""

import agent_bom.canonical_ids as ids
from agent_bom.graph.asset_identity import strong_keys
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.finding_row_projection import project_finding_rows
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _project_agent(config_path: str) -> dict:
    return {
        "name": "project:repo",
        "agent_type": "custom",
        "source": "project-config",
        "config_path": config_path,
        "mcp_servers": [{"name": "fs", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}],
    }


def _agent_nodes(report: dict) -> dict[str, UnifiedNode]:
    graph = build_unified_graph_from_report(report)
    return {node.id: node for node in graph.nodes.values() if node.entity_type == EntityType.AGENT}


def test_same_named_project_configs_stay_two_agents_in_any_order():
    first, second = _project_agent("/repo/.mcp.json"), _project_agent("/repo/.vscode/mcp.json")
    forward = _agent_nodes({"agents": [first, second]})
    backward = _agent_nodes({"agents": [second, first]})
    assert len(forward) == 2
    assert {node_id: node.attributes["config_path"] for node_id, node in forward.items()} == {
        node_id: node.attributes["config_path"] for node_id, node in backward.items()
    }


def test_endpoint_scope_retains_legacy_receipt_while_escaping_name():
    agent = {**_project_agent("/repo/.mcp.json"), "source_id": "laptop-1"}
    assert ids.agent_graph_id_for(agent) == "agent:laptop-1:project%3Arepo"
    assert ids.previous_agent_graph_ids(agent) == ["agent:laptop-1:project:repo"]


def test_previous_name_only_id_is_an_alias_only_when_unambiguous():
    single = _agent_nodes({"agents": [_project_agent("/repo/.mcp.json")]})
    (only,) = single.values()
    assert "agent:project:repo" in only.attributes["identity"]["aliases"]
    pair = _agent_nodes({"agents": [_project_agent("/repo/.mcp.json"), _project_agent("/repo/.vscode/mcp.json")]})
    assert all("agent:project:repo" not in (node.attributes.get("identity") or {}).get("aliases", []) for node in pair.values())


def test_cspm_row_with_other_account_arn_never_binds_to_same_label():
    graph = UnifiedGraph()
    inventory_id = "cloud_resource:aws:arn:aws:rds:us-east-1:111111111111:db:prod"
    graph.add_node(UnifiedNode(id=inventory_id, entity_type=EntityType.CLOUD_RESOURCE, label="prod", data_sources=["cloud-inventory"]))
    arn = "arn:aws:rds:us-east-1:222222222222:db:prod"
    row = {
        "id": "f-1",
        "source": "CLOUD_CIS",
        "finding_type": "CIS_FAIL",
        "title": "RDS public",
        "severity": "high",
        "asset": {"name": "prod", "identifier": arn, "asset_type": "cloud_resource", "provider": "aws"},
    }
    project_finding_rows(graph, [row])
    assert graph.nodes[inventory_id].data_sources == ["cloud-inventory"]
    assert not graph.edges_from(inventory_id) and not graph.edges_to(inventory_id)
    assert f"cloud_resource:aws:{arn}" in graph.nodes


def test_name_only_row_proposes_a_candidate_instead_of_merging():
    graph = UnifiedGraph()
    inventory_id = "cloud_resource:aws:arn:aws:rds:us-east-1:111111111111:db:prod"
    graph.add_node(UnifiedNode(id=inventory_id, entity_type=EntityType.CLOUD_RESOURCE, label="prod", data_sources=["cloud-inventory"]))
    row = {
        "id": "f-2",
        "source": "CLOUD_CIS",
        "finding_type": "CIS_FAIL",
        "title": "RDS public",
        "severity": "high",
        "asset": {"name": "prod", "asset_type": "cloud_resource", "provider": "aws"},
    }
    project_finding_rows(graph, [row])
    assert graph.nodes[inventory_id].data_sources == ["cloud-inventory"]
    touching = [*graph.edges_from(inventory_id), *graph.edges_to(inventory_id)]
    assert touching and {edge.relationship for edge in touching} == {RelationshipType.POSSIBLY_CORRELATES_WITH}


def _inventory(account: str, **extra) -> dict:
    return {"provider": "aws", "status": "ok", "account_id": account, **extra}


def test_dspm_databases_with_one_name_in_two_accounts_stay_apart():
    report = {
        "cloud_inventory": [
            _inventory(account, dspm_databases=[{"name": "prod", "engine": "postgres", "account_id": account}])
            for account in ("111111111111", "222222222222")
        ]
    }
    graph = build_unified_graph_from_report(report)
    dbs = [node for node in graph.nodes.values() if node.attributes.get("cloud_service") == "dspm-database"]
    assert sorted(node.attributes["account_id"] for node in dbs) == ["111111111111", "222222222222"]


def test_arnless_principals_with_one_name_in_two_accounts_stay_apart():
    report = {"cloud_inventory": [_inventory(account, users=[{"name": "Admin"}]) for account in ("111111111111", "222222222222")]}
    graph = build_unified_graph_from_report(report)
    admins = [node for node in graph.nodes.values() if node.attributes.get("principal_name") == "Admin"]
    assert len(admins) == 2


def _okta_user(org: str) -> UnifiedNode:
    attrs = {"cloud_provider": "okta", "principal_id": "00u1"}
    if org:
        attrs["org_id"] = org
    return UnifiedNode(id=f"user:okta:{org}:00u1", entity_type=EntityType.USER, label="alice", attributes=attrs)


def test_idp_principal_key_carries_the_org():
    key_a = {key.value for key in strong_keys(_okta_user("org-a")) if key.namespace == "principal_id"}
    key_b = {key.value for key in strong_keys(_okta_user("org-b")) if key.namespace == "principal_id"}
    assert key_a and key_b and key_a.isdisjoint(key_b)
    assert not [key for key in strong_keys(_okta_user("")) if key.namespace == "principal_id"]


def test_project_agent_id_matches_between_model_and_serialized_report():
    from agent_bom.models import Agent, AgentType, AIBOMReport
    from agent_bom.output.json_fmt import to_json

    agent = Agent(name="project:repo", agent_type=AgentType.CUSTOM, config_path="/home/u/repo/.vscode/mcp.json", source="project-config")
    (serialized,) = to_json(AIBOMReport(agents=[agent], tool_version="0.0.0"))["agents"]
    assert ids.agent_graph_id_for(agent) == ids.agent_graph_id_for(serialized) != "agent:project:repo"


def test_arnless_groups_with_one_name_in_two_accounts_stay_apart():
    report = {"cloud_inventory": [_inventory(account, groups=[{"name": "Admins"}]) for account in ("111111111111", "222222222222")]}
    graph = build_unified_graph_from_report(report)
    assert len([node for node in graph.nodes.values() if node.entity_type == EntityType.GROUP and node.label == "Admins"]) == 2


def test_short_name_row_binds_only_inside_its_account():
    graph = UnifiedGraph()
    for account in ("111111111111", "222222222222"):
        graph.add_node(
            UnifiedNode(
                id=f"cloud_resource:aws:{account}:bucket:logs",
                entity_type=EntityType.CLOUD_RESOURCE,
                label="logs",
                attributes={"cloud_provider": "aws", "resource_name": "logs", "resource_type": "bucket", "account_id": account},
            )
        )
    row = {
        "id": "f-3",
        "source": "CLOUD_CIS",
        "finding_type": "CIS_FAIL",
        "title": "Bucket public",
        "severity": "high",
        "account_ref": "222222222222",
        "asset": {"name": "logs", "identifier": "bucket/logs", "asset_type": "cloud_resource", "provider": "aws"},
    }
    project_finding_rows(graph, [row])
    bound = [edge for edge in graph.edges if "cloud_resource:aws:222222222222:bucket:logs" in (edge.source, edge.target)]
    assert bound and not [edge for edge in graph.edges if "cloud_resource:aws:111111111111:bucket:logs" in (edge.source, edge.target)]
