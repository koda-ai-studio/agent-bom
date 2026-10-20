"""GCP names are unique only inside a project (and zone/region); fallback ids must carry that scope."""

from __future__ import annotations

import types
from typing import Any

import pytest

from agent_bom.cloud.azure_inv.network import _normalize_nsg
from agent_bom.cloud.gcp_inv import compute_storage, network
from tests._sdk_stub_helpers import patch_sdk_namespace

CL = "https://www.googleapis.com/compute/v1/projects/proj-a"


class _Obj:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _client(**methods: Any) -> type:
    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    for name, result in methods.items():
        setattr(_Client, name, lambda self, *a, _r=result, **k: _r)
    return _Client


def _sdk(**clients: Any) -> Any:
    compute = types.ModuleType("google.cloud.compute_v1")
    container = types.ModuleType("google.cloud.container_v1")
    for name, cls in clients.items():
        setattr(container if name == "ClusterManagerClient" else compute, name, cls)
    cloud = types.ModuleType("google.cloud")
    cloud.compute_v1 = compute  # type: ignore[attr-defined]
    cloud.container_v1 = container  # type: ignore[attr-defined]
    google = types.ModuleType("google")
    google.cloud = cloud  # type: ignore[attr-defined]
    return patch_sdk_namespace(
        {"google": google, "google.cloud": cloud, "google.cloud.compute_v1": compute, "google.cloud.container_v1": container},
        "google",
    )


def _routers(project: str, region: str) -> list[tuple[str, Any]]:
    link = f"https://www.googleapis.com/compute/v1/projects/{project}"
    return [
        (
            f"regions/{region}",
            _Obj(
                routers=[
                    _Obj(
                        name="edge",
                        id="",
                        network=f"{link}/global/networks/default",
                        region=f"{link}/regions/{region}",
                        nats=[_Obj(name="egress")],
                    ),
                    _Obj(name="numbered", id="4242", network="default", region=f"{link}/regions/{region}", nats=None),
                ]
            ),
        )
    ]


def _discover_routers(project: str, region: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with _sdk(RoutersClient=_client(aggregated_list=_routers(project, region))):
        return network._discover_routers(project, credentials=None, warnings=[])


def test_cloud_nat_id_is_the_project_region_router_scoped_path() -> None:
    nats, routers = _discover_routers("proj-a", "us-central1")
    assert [nat["id"] for nat in nats] == ["projects/proj-a/regions/us-central1/routers/edge/nats/egress"]
    # A router's numeric id stays primary; only the missing-id router falls back to its path.
    assert [router["id"] for router in routers] == ["projects/proj-a/regions/us-central1/routers/edge", "4242"]


def test_same_named_router_nats_in_other_projects_and_regions_get_distinct_ids() -> None:
    ids = {
        nat["id"]
        for project, region in (("proj-a", "us-central1"), ("proj-b", "us-central1"), ("proj-a", "europe-west1"))
        for nat in _discover_routers(project, region)[0]
    }
    assert len(ids) == 3


def test_instance_without_numeric_id_falls_back_to_zone_scoped_path() -> None:
    bare = _Obj(name="web", zone=f"{CL}/zones/us-central1-a", network_interfaces=[], service_accounts=[], tags=None)
    assert compute_storage._normalize_instance(bare, name="web", project_id="proj-a")["instance_id"] == (
        "projects/proj-a/zones/us-central1-a/instances/web"
    )
    numbered = _Obj(id=987, name="web", zone=f"{CL}/zones/us-central1-a", network_interfaces=[], service_accounts=[], tags=None)
    assert compute_storage._normalize_instance(numbered, name="web", project_id="proj-a")["instance_id"] == "987"


def test_global_and_zonal_fallbacks_are_project_scoped() -> None:
    _subnet = _Obj(name="sub", network="default", region=f"{CL}/regions/us-central1")
    sdk = _sdk(
        NetworksClient=_client(list=[_Obj(name="default", id="", self_link=""), _Obj(name="numbered", id="77", self_link="")]),
        SubnetworksClient=_client(aggregated_list=[("regions/us-central1", _Obj(subnetworks=[_subnet]))]),
        TargetHttpProxiesClient=_client(list=[_Obj(name="web-proxy")]),
        TargetHttpsProxiesClient=_client(list=[_Obj(name="web-proxy")]),
        SecurityPoliciesClient=_client(list=[_Obj(name="armor")]),
        DisksClient=_client(aggregated_list=[("zones/us-central1-a", _Obj(disks=[_Obj(name="boot", zone=f"{CL}/zones/us-central1-a")]))]),
        ClusterManagerClient=_client(list_clusters=_Obj(clusters=[_Obj(name="gke", location="us-central1")])),
    )
    with sdk:
        networks = network._discover_vpc_networks("proj-a", credentials=None, warnings=[])
        subnets = network._discover_subnets(
            network._discover_subnets_by_network("proj-a", credentials=None, warnings=[]), project_id="proj-a"
        )
        proxies = network._discover_target_proxies("proj-a", credentials=None, warnings=[])
        policies = network._discover_security_policies("proj-a", credentials=None, warnings=[])
        disks = compute_storage._discover_disks("proj-a", credentials=None, warnings=[])
        clusters = compute_storage._discover_gke_clusters("proj-a", credentials=None, warnings=[])

    assert [n["id"] for n in networks] == ["projects/proj-a/global/networks/default", "77"]
    assert [s["id"] for s in subnets] == ["projects/proj-a/regions/us-central1/subnetworks/sub"]
    # HTTP and HTTPS target proxies share a name space per kind, not with each other.
    assert [p["id"] for p in proxies] == [
        "projects/proj-a/global/targetHttpProxies/web-proxy",
        "projects/proj-a/global/targetHttpsProxies/web-proxy",
    ]
    assert [p["id"] for p in policies] == ["projects/proj-a/global/securityPolicies/armor"]
    assert [d["id"] for d in disks] == ["projects/proj-a/zones/us-central1-a/disks/boot"]
    assert [c["id"] for c in clusters] == ["projects/proj-a/locations/us-central1/clusters/gke"]


def test_backend_service_fallback_is_scoped_and_policy_join_follows_it() -> None:
    backends = [
        ("global", _Obj(backend_services=[_Obj(name="api", security_policy=f"{CL}/global/securityPolicies/armor")])),
        ("regions/us-east1", _Obj(backend_services=[_Obj(name="api", region=f"{CL}/regions/us-east1")])),
    ]
    with _sdk(BackendServicesClient=_client(aggregated_list=backends)):
        from agent_bom.cloud import gcp_inventory

        lbs, by_policy = gcp_inventory._discover_load_balancers("proj-a", credentials=None, warnings=[])
    ids = [lb["id"] for lb in lbs if lb["lb_type"] == "backend-service"]
    assert ids == ["projects/proj-a/global/backendServices/api", "projects/proj-a/regions/us-east1/backendServices/api"]
    assert by_policy == {"armor": ["projects/proj-a/global/backendServices/api"]}


def test_blank_name_or_project_never_invents_a_scoped_id() -> None:
    from agent_bom.cloud.gcp_inv._base import _scoped_name

    assert _scoped_name("proj-a", "regions/us-central1", "subnetworks", "") == ""
    assert _scoped_name("", "global", "networks", "default") == ""
    assert _scoped_name("proj-a", "", "disks", "boot") == "projects/proj-a/disks/boot"


@pytest.mark.parametrize(
    ("nsg_id", "expected"),
    [
        (
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web",
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web",
        ),
        ("", "subscriptions/sub-1/networkSecurityGroups/web"),
    ],
    ids=["arm-id-kept", "missing-id-subscription-scoped"],
)
def test_azure_nsg_fallback_is_subscription_scoped(nsg_id: str, expected: str) -> None:
    record = _normalize_nsg(_Obj(security_rules=[]), nsg_id=nsg_id, name="web", subscription_id="sub-1")
    assert record["group_id"] == expected
    assert record["name"] == "web"
