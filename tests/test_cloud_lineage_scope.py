"""Cloud lineage resource ids stay scoped where provider ids are account-local."""

from __future__ import annotations

from agent_bom.graph import build_unified_graph_from_report
from agent_bom.graph.types import EntityType


def _agent(account: str, resource_id: str, *, service: str = "bedrock", resource_type: str = "agent", region: str = "us-east-1") -> dict:
    return {
        "name": f"bedrock:{resource_id}",
        "agent_type": "custom",
        "source": f"aws-{service}",
        "config_path": f"aws://{account}/{region}/{resource_id}",
        "mcp_servers": [],
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": service,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_name": resource_id,
                "location": region,
                "scope": {"account_id": account},
            }
        },
    }


def _resources(agents: list[dict]) -> list:
    graph = build_unified_graph_from_report({"scan_id": "s", "agents": agents, "blast_radius": []}, scan_id="s", tenant_id="t")
    return [n for n in graph.nodes.values() if n.entity_type == EntityType.CLOUD_RESOURCE]


def test_same_short_id_in_two_accounts_is_two_nodes() -> None:
    nodes = _resources([_agent("111111111111", "AGENT123"), _agent("222222222222", "AGENT123")])
    assert len(nodes) == 2
    for node in nodes:
        assert node.attributes["identity"]["aliases"] == ["cloud_resource:aws:bedrock:agent:AGENT123"]
    assert {n.id for n in nodes} == {
        "cloud_resource:aws:bedrock:agent:111111111111/us-east-1:AGENT123",
        "cloud_resource:aws:bedrock:agent:222222222222/us-east-1:AGENT123",
    }


def test_same_short_id_in_two_regions_is_two_nodes() -> None:
    nodes = _resources([_agent("111111111111", "AGENT123"), _agent("111111111111", "AGENT123", region="eu-west-1")])
    assert len(nodes) == 2


def test_same_short_id_in_one_account_is_one_node() -> None:
    nodes = _resources([_agent("111111111111", "AGENT123"), _agent("111111111111", "AGENT123")])
    assert len(nodes) == 1


def test_full_arn_keeps_its_id() -> None:
    arn = "arn:aws:bedrock:us-east-1:111111111111:agent/AGENT123"
    nodes = _resources([_agent("111111111111", arn)])
    assert [n.id for n in nodes] == [f"cloud_resource:aws:bedrock:agent:{arn}"]
    assert "identity" not in nodes[0].attributes


def test_arn_without_account_segment_is_scoped_by_account() -> None:
    arn = "arn:aws:bedrock:us-east-1:agent/AGENT123"
    nodes = _resources([_agent("111111111111", arn), _agent("222222222222", arn)])
    assert len(nodes) == 2


def test_globally_unique_ec2_instance_id_keeps_inventory_join_id() -> None:
    nodes = _resources([_agent("111111111111", "i-0abc12345def67890", service="ec2", resource_type="instance")])
    assert [n.id for n in nodes] == ["cloud_resource:aws:ec2:instance:i-0abc12345def67890"]


def test_short_id_without_account_stays_unscoped() -> None:
    agent = _agent("", "AGENT123")
    agent["metadata"]["cloud_origin"]["scope"] = {}
    agent["metadata"]["cloud_origin"]["location"] = ""
    nodes = _resources([agent])
    assert [n.id for n in nodes] == ["cloud_resource:aws:bedrock:agent:AGENT123"]
