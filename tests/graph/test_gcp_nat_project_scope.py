"""Cloud NAT configs are router sub-resources; their graph identity must carry project + region."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report

NAT_A = "cloud_resource:gcp:network:nat_gateway:projects/proj-a/regions/us-central1/routers/edge/nats/egress"
NAT_B = "cloud_resource:gcp:network:nat_gateway:projects/proj-b/regions/us-central1/routers/edge/nats/egress"


def _nat_inventory(project: str, nat_id: str) -> dict[str, Any]:
    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": project,
        "account_id": project,
        "buckets": [],
        "instances": [],
        "firewalls": [],
        "service_accounts": [],
        "nat_gateways": [
            {"id": nat_id, "name": "egress", "vpc_id": "default", "subnet_id": "", "location": "us-central1", "account_id": project}
        ],
    }


def nat_inventories(*, legacy: bool) -> list[dict[str, Any]]:
    return [
        _nat_inventory(project, "edge/egress" if legacy else f"projects/{project}/regions/us-central1/routers/edge/nats/egress")
        for project in ("proj-a", "proj-b")
    ]


def _nat_nodes(inventories: list[dict[str, Any]]) -> dict[str, Any]:
    graph = build_unified_graph_from_report({"agents": [], "cloud_inventory": inventories})
    return {nid: node for nid, node in graph.nodes.items() if nid.startswith("cloud_resource:gcp:network:nat_gateway:")}


@pytest.mark.parametrize("legacy", [False, True], ids=["scoped-collector-ids", "legacy-router-nat-ids"])
@pytest.mark.parametrize("reverse", [False, True], ids=["a-then-b", "b-then-a"])
def test_same_named_router_nats_in_two_projects_stay_distinct(legacy: bool, reverse: bool) -> None:
    inventories = nat_inventories(legacy=legacy)
    if reverse:
        inventories.reverse()
    nats = _nat_nodes(inventories)
    assert set(nats) == {NAT_A, NAT_B}
    assert nats[NAT_A].attributes["account_id"] == "proj-a"
    assert nats[NAT_B].attributes["account_id"] == "proj-b"
    assert {node.attributes["resource_name"] for node in nats.values()} == {"egress"}


def test_legacy_nat_id_without_region_is_still_project_scoped() -> None:
    inventory = _nat_inventory("proj-a", "edge/egress")
    inventory["nat_gateways"][0]["location"] = ""
    assert set(_nat_nodes([inventory])) == {"cloud_resource:gcp:network:nat_gateway:projects/proj-a/routers/edge/nats/egress"}
