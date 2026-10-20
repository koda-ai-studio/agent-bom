"""A Snowflake external table reads an AWS S3 bucket through a storage integration's IAM role.

Every estate path stayed inside one vendor. Each Snowflake account now records
one S3 storage integration (the IAM role it assumes, which trusts the Snowflake
account), one external stage over it and one external table reading the stage,
as labelled synthetic recorded data. The graph draws them with existing
relationship types, so one traversal starts in Snowflake and ends in AWS.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import estate_account_node_id, project_estate_into_graph
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType


@pytest.fixture(scope="module")
def estate():
    return build_demo_estate(tenant_id="default")


@pytest.fixture(scope="module")
def graph(estate):
    built = UnifiedGraph(scan_id="estate-cross-vendor", tenant_id="default")
    project_estate_into_graph(built, estate, findings=build_estate_findings(estate))
    return built


def _integrations(estate):
    return [a for a in estate.assets if a.resource_type == "storage_integration"]


def test_each_snowflake_account_records_one_s3_storage_integration(estate) -> None:
    by_id = {a.asset_id: a for a in estate.assets}
    integrations = _integrations(estate)
    snowflake_accounts = {a.account_scope for a in estate.assets if a.resource_type == "stage"}
    assert sorted(i.account_scope for i in integrations) == sorted(snowflake_accounts)
    for integration in integrations:
        bucket, role = by_id[integration.tags["integration_location"]], by_id[integration.tags["integration_role"]]
        assert integration.provider == "snowflake" and integration.tags["integration_source"] == "synthetic-demo-integration"
        assert (bucket.provider, bucket.resource_type) == ("aws", "bucket")
        assert (role.provider, role.resource_type, role.account_scope) == ("aws", "iam_role", bucket.account_scope)
        # Never linked across environments.
        assert role.environment == bucket.environment == integration.environment
        assert role.tags["integration_source"] == "synthetic-demo-integration"
        assert integration.tags["storage_aws_role_arn"] == f"arn:aws:iam::{role.account_scope}:role/{role.display_name}"
        stages = [a for a in estate.assets if a.tags.get("storage_integration") == integration.asset_id]
        assert [(s.provider, s.resource_type, s.account_scope) for s in stages] == [("snowflake", "stage", integration.account_scope)]
        readers = [a for a in estate.assets if a.tags.get("external_stage") == stages[0].asset_id]
        assert [(r.provider, r.resource_type, r.account_scope) for r in readers] == [("snowflake", "table", integration.account_scope)]


def test_cross_vendor_edges_use_existing_relationships(estate, graph) -> None:
    edges = {(e.source, e.target, e.relationship) for e in graph.edges}
    for integration in _integrations(estate):
        role, bucket = integration.tags["integration_role"], integration.tags["integration_location"]
        stage = next(a.asset_id for a in estate.assets if a.tags.get("storage_integration") == integration.asset_id)
        table = next(a.asset_id for a in estate.assets if a.tags.get("external_stage") == stage)
        assert (table, stage, RelationshipType.DEPENDS_ON) in edges
        assert (stage, integration.asset_id, RelationshipType.DEPENDS_ON) in edges
        assert (integration.asset_id, role, RelationshipType.ASSUMES) in edges
        assert (role, estate_account_node_id(estate, integration.account_scope), RelationshipType.TRUSTS) in edges
        assert (role, bucket, RelationshipType.CAN_ACCESS) in edges


def test_one_traversal_runs_from_snowflake_into_aws(tmp_path, estate, graph) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    integration = _integrations(estate)[0]
    stage = next(a.asset_id for a in estate.assets if a.tags.get("storage_integration") == integration.asset_id)
    table = next(a.asset_id for a in estate.assets if a.tags.get("external_stage") == stage)
    expected = [table, stage, integration.asset_id, integration.tags["integration_role"], integration.tags["integration_location"]]
    paths, _reachable, _truncated, _limited = store.bfs_paths(
        tenant_id="default", scan_id=graph.scan_id, source=table, max_depth=6, traversable_only=True
    )
    assert expected in paths
    providers = [graph.nodes[hop].attributes["cloud_provider"] for hop in expected]
    assert providers == ["snowflake", "snowflake", "snowflake", "aws", "aws"]


def test_no_same_environment_bucket_links_nothing_and_says_why() -> None:
    from agent_bom.demo_estate.enterprise import EstateAsset
    from agent_bom.demo_estate.estate_external_stages import record_external_stages

    def asset(asset_id: str, provider: str, resource_type: str, scope: str, environment: str) -> EstateAsset:
        return EstateAsset(
            asset_id=asset_id,
            tenant_id="t",
            provider=provider,
            resource_type=resource_type,
            native_id=asset_id,
            display_name=asset_id.rsplit(":", 1)[-1],
            environment=environment,
            account_scope=scope,
            owner="owner@example.test",
            cost_center="CC-1",
        )

    assets = (
        asset("snowflake:stage:SF:s1", "snowflake", "stage", "SF", "staging"),
        asset("snowflake:table:SF:t1", "snowflake", "table", "SF", "staging"),
        asset("aws:bucket:111:b1", "aws", "bucket", "111", "production"),
    )
    recorded = {a.asset_id: a for a in record_external_stages(assets)}
    assert not [a for a in recorded.values() if a.resource_type in {"storage_integration", "iam_role"}]
    stage = recorded["snowflake:stage:SF:s1"]
    assert "storage_integration" not in stage.tags
    assert stage.tags["integration_unlinked_reason"] == "no_same_environment_s3_bucket"
