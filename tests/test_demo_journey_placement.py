"""Ordinary synthetic MCP journeys follow recorded workload placements."""

from datetime import datetime, timezone

import pytest

from agent_bom.demo_estate.enterprise_journeys import build_journeys
from agent_bom.demo_estate.enterprise_scale import ScaleProfile, build_scaled_estate


def test_default_mcp_journeys_follow_recorded_host_and_environment():
    estate = build_scaled_estate(ScaleProfile(accounts_per_cloud=2, resources_per_account=6, events_per_asset=1))
    assets = {asset.asset_id: asset for asset in estate.assets}
    calls = [event for event in estate.observations if event.event_type == "tools/call" and event.event_id.startswith("evtj-")]
    assert calls
    for event in calls:
        members = [assets[key] for key in event.resource_ids]
        workload = next(asset for asset in members if asset.resource_type == "deployment")
        server = next(asset for asset in members if asset.resource_type == "server")
        tool = next(asset for asset in members if asset.resource_type == "tool")
        assert server.tags["deployment"] == workload.asset_id
        assert tool.tags["mcp_server"] == server.asset_id
        assert {workload.environment, server.environment, tool.environment} == {workload.environment}
        assert {workload.account_scope, server.account_scope, tool.account_scope} == {workload.account_scope}
        assert workload.tags["host_provider"] == server.tags["host_provider"]


@pytest.mark.parametrize("invalid", ["missing", "tenant", "environment"])
def test_unrecorded_or_conflicting_mcp_placement_does_not_invent_a_journey(invalid):
    estate = build_scaled_estate(ScaleProfile(accounts_per_cloud=2, resources_per_account=6, events_per_asset=1))
    assets = []
    for asset in estate.assets:
        if asset.resource_type == "server":
            changes = {"tags": {key: value for key, value in asset.tags.items() if key != "deployment"}}
            if invalid == "tenant":
                changes = {"tenant_id": "unrelated-tenant"}
            elif invalid == "environment":
                changes = {"environment": "unrelated-environment"}
            asset = asset.model_copy(update=changes)
        assets.append(asset)
    assert build_journeys(assets, tenant_id=estate.tenant_id, count=1, epoch=datetime(2026, 1, 1, tzinfo=timezone.utc)) == ()
