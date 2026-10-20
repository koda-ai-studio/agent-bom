"""A Snowflake external table reaches an AWS S3 bucket through correlation, not a drawn edge.

Every estate path stayed inside one vendor. Each Snowflake account now records
the raw facts the two connectors would collect, as labelled synthetic data: a
storage integration (``storage_aws_role_arn``, ``storage_aws_iam_user_arn``,
``storage_aws_external_id``, ``storage_allowed_locations``), the IAM role created
for it (its ARN and trust policy), the bucket's ARN, an external stage over the
integration and an external table over the stage. The demo draws only the
Snowflake-internal stage lineage; the cross-vendor edges come from
:mod:`agent_bom.graph.storage_integration_correlation`, joined on those
recorded identifiers.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.storage_integration_correlation import SOURCE as CORRELATOR
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


def _recorded(estate, integration):
    """The role and bucket the integration's recorded identifiers name, found by identifier only."""
    role = next(a for a in estate.assets if a.resource_type == "iam_role" and a.native_id == integration.tags["storage_aws_role_arn"])
    location = integration.tags["storage_allowed_locations"]
    bucket_arn = "arn:aws:s3:::" + location.removeprefix("s3://").split("/", 1)[0]
    bucket = next(a for a in estate.assets if a.resource_type == "bucket" and a.tags.get("arn") == bucket_arn)
    stage = next(a for a in estate.assets if a.tags.get("storage_integration") == integration.asset_id)
    table = next(a for a in estate.assets if a.tags.get("external_stage") == stage.asset_id)
    return role, bucket, stage, table


def test_each_snowflake_account_records_the_connector_facts(estate) -> None:
    integrations = _integrations(estate)
    snowflake_accounts = {a.account_scope for a in estate.assets if a.resource_type == "stage"}
    assert sorted(i.account_scope for i in integrations) == sorted(snowflake_accounts)
    for integration in integrations:
        role, bucket, stage, table = _recorded(estate, integration)
        assert integration.provider == "snowflake" and integration.tags["integration_source"] == "synthetic-demo-integration"
        assert "integration_role" not in integration.tags and "integration_location" not in integration.tags
        assert (bucket.provider, role.provider, role.account_scope) == ("aws", "aws", bucket.account_scope)
        # Never linked across environments.
        assert role.environment == bucket.environment == integration.environment
        assert role.tags["trust_principals"] == integration.tags["storage_aws_iam_user_arn"]
        assert role.tags["trust_external_ids"] == integration.tags["storage_aws_external_id"]
        assert (stage.provider, table.provider) == ("snowflake", "snowflake")


def test_the_demo_draws_no_cross_vendor_edge_itself(estate) -> None:
    from agent_bom.demo_estate import estate_graph

    unlinked = UnifiedGraph(scan_id="estate-no-correlation", tenant_id="default")
    original = estate_graph.correlate_storage_integrations
    estate_graph.correlate_storage_integrations = lambda _graph: 0
    try:
        project_estate_into_graph(unlinked, estate)
    finally:
        estate_graph.correlate_storage_integrations = original
    integration_ids = {i.asset_id for i in _integrations(estate)}
    crossing = [
        e
        for e in unlinked.edges
        if e.source in integration_ids and e.relationship in {RelationshipType.ASSUMES, RelationshipType.CAN_ACCESS}
    ]
    assert crossing == []


def test_the_correlator_joins_snowflake_to_aws_on_recorded_identifiers(estate, graph) -> None:
    edges = {(e.source, e.target, e.relationship): e for e in graph.edges}
    for integration in _integrations(estate):
        role, bucket, stage, table = _recorded(estate, integration)
        assert (table.asset_id, stage.asset_id, RelationshipType.DEPENDS_ON) in edges
        assert (stage.asset_id, integration.asset_id, RelationshipType.DEPENDS_ON) in edges
        assumes = edges[(integration.asset_id, role.asset_id, RelationshipType.ASSUMES)]
        access = edges[(integration.asset_id, bucket.asset_id, RelationshipType.CAN_ACCESS)]
        assert assumes.evidence["source"] == access.evidence["source"] == CORRELATOR
        assert assumes.evidence["derived_via"] == "recorded_identifier_match"


def test_one_traversal_runs_from_snowflake_into_aws(tmp_path, estate, graph) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    integration = _integrations(estate)[0]
    role, bucket, stage, table = _recorded(estate, integration)
    expected = [table.asset_id, stage.asset_id, integration.asset_id, bucket.asset_id]
    paths, _reachable, _truncated, _limited = store.bfs_paths(
        tenant_id="default", scan_id=graph.scan_id, source=table.asset_id, max_depth=6, traversable_only=True
    )
    assert expected in paths
    assert [table.asset_id, stage.asset_id, integration.asset_id, role.asset_id] in paths
    assert [graph.nodes[hop].attributes["cloud_provider"] for hop in expected] == ["snowflake", "snowflake", "snowflake", "aws"]


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
