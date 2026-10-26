"""Read-only GPU node-pool inventory for EKS, GKE and AKS from recorded API responses."""

from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Any

from agent_bom.cloud.gpu_node_pools import gpu_pool_node_id, gpu_pools
from tests._sdk_stub_helpers import patch_sdk_namespace

FIXTURES = Path(__file__).parent / "fixtures" / "gpu_infra"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


_MAP_FIELDS = {"labels", "resource_labels", "tags", "node_labels"}


def _ns(value: Any) -> Any:
    """SDK-shaped object: messages become attributes, map fields stay mappings."""
    if isinstance(value, dict):
        return types.SimpleNamespace(**{key: item if key in _MAP_FIELDS else _ns(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_ns(item) for item in value]
    return value


# ── EKS ──────────────────────────────────────────────────────────────────────


class _Pages:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return self.pages


class _EksClient:
    def __init__(self, recorded: dict[str, Any], *, deny_nodegroups: bool = False) -> None:
        self.recorded = recorded
        self.deny_nodegroups = deny_nodegroups
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_paginator(self, op: str) -> _Pages:
        self.calls.append((op, {}))
        if op == "list_clusters":
            return _Pages([{"clusters": [self.recorded["cluster"]["name"]]}])
        if op == "list_nodegroups":
            if self.deny_nodegroups:
                raise PermissionError("AccessDeniedException: not authorized to perform eks:ListNodegroups")
            return _Pages([{"nodegroups": [ng["nodegroup"]["nodegroupName"] for ng in self.recorded["nodegroups"]]}])
        raise AssertionError(op)

    def describe_cluster(self, name: str) -> dict[str, Any]:
        self.calls.append(("describe_cluster", {"name": name}))
        return {"cluster": self.recorded["cluster"]}

    def describe_nodegroup(self, clusterName: str, nodegroupName: str) -> dict[str, Any]:  # noqa: N803 — boto3 API names
        self.calls.append(("describe_nodegroup", {"clusterName": clusterName, "nodegroupName": nodegroupName}))
        return next(ng for ng in self.recorded["nodegroups"] if ng["nodegroup"]["nodegroupName"] == nodegroupName)


class _Session:
    def __init__(self, client: _EksClient) -> None:
        self._client = client

    def client(self, svc: str, **_kwargs: Any) -> _EksClient:
        assert svc == "eks"
        return self._client


def test_eks_node_groups_capture_gpu_capacity_driver_and_identity() -> None:
    from agent_bom.cloud.aws_inv.services import _discover_eks

    client = _EksClient(_load("eks_describe_nodegroups.json"))
    warnings: list[str] = []
    (cluster,) = _discover_eks(_Session(client), "us-east-1", account_id="111122223333", warnings=warnings)
    assert warnings == []
    pools = {pool["name"]: pool for pool in cluster["node_pools"]}
    assert set(pools) == {"gpu-a10g", "train-custom", "system"}

    a10g = pools["gpu-a10g"]
    assert (a10g["gpu"], a10g["gpu_vendor"], a10g["accelerator_type"], a10g["accelerators_per_node"]) == (True, "nvidia", "A10G", 1)
    assert a10g["gpu_driver"] == {"management": "provider-managed", "setting": "AL2023_x86_64_NVIDIA"}
    assert (a10g["min_nodes"], a10g["max_nodes"], a10g["node_count"]) == (1, 6, 2)
    assert a10g["node_identity"] == "arn:aws:iam::111122223333:role/ml-prod-gpu-node"
    assert a10g["ssh_open_to_internet"] is True
    assert a10g["cluster_key"] == "arn:aws:eks:us-east-1:111122223333:cluster/ml-prod"

    custom = pools["train-custom"]
    assert custom["gpu_driver"]["management"] == "user-managed"
    assert custom["accelerators_per_node"] == 8
    assert custom["taints"] == [{"key": "nvidia.com/gpu", "value": "true", "effect": "NO_SCHEDULE"}]
    assert pools["system"]["gpu"] is False
    assert [p["name"] for p in gpu_pools([cluster])] == ["gpu-a10g", "train-custom"]
    assert {op for op, _ in client.calls} == {"list_clusters", "describe_cluster", "list_nodegroups", "describe_nodegroup"}


def test_eks_node_group_denial_degrades_to_a_missing_permission() -> None:
    from agent_bom.cloud.aws_inv.services import _discover_eks

    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    (cluster,) = _discover_eks(
        _Session(_EksClient(_load("eks_describe_nodegroups.json"), deny_nodegroups=True)),
        "us-east-1",
        account_id="111122223333",
        warnings=warnings,
        missing=missing,
    )
    assert cluster["node_pools"] == []
    assert cluster["node_pools_complete"] is False
    assert any(m.get("permission") == "eks:ListNodegroups" for m in missing)


# ── GKE ──────────────────────────────────────────────────────────────────────


def _gke_module(clusters: list[dict[str, Any]]) -> dict[str, Any]:
    class _Client:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def list_clusters(self, parent: str) -> Any:
            assert parent == "projects/example-ml-project/locations/-"
            return types.SimpleNamespace(clusters=_ns(clusters))

    container = types.ModuleType("google.cloud.container_v1")
    container.ClusterManagerClient = _Client  # type: ignore[attr-defined]
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")
    cloud.container_v1 = container  # type: ignore[attr-defined]
    google.cloud = cloud  # type: ignore[attr-defined]
    return {"google": google, "google.cloud": cloud, "google.cloud.container_v1": container}


def test_gke_node_pools_capture_accelerators_sharing_and_driver_install() -> None:
    from agent_bom.cloud.gcp_inv.compute_storage import _discover_gke_clusters

    warnings: list[str] = []
    with patch_sdk_namespace(_gke_module(_load("gke_clusters.json")), "google"):
        (cluster,) = _discover_gke_clusters("example-ml-project", credentials=None, warnings=warnings)
    assert warnings == []
    pools = {pool["name"]: pool for pool in cluster["node_pools"]}
    l4 = pools["l4-shared"]
    assert (l4["gpu"], l4["accelerator_type"], l4["accelerators_per_node"]) == (True, "nvidia-l4", 1)
    assert l4["gpu_sharing"] == {"strategy": "time-slicing", "max_shared_clients": 4}
    assert l4["gpu_driver"] == {"management": "provider-managed", "setting": "LATEST"}
    assert l4["node_identity"] == "default"
    assert (l4["min_nodes"], l4["max_nodes"]) == (0, 4)
    assert l4["cluster_key"] == "projects/example-ml-project/locations/us-central1/clusters/vision"
    assert l4["pool_id"] == "projects/example-ml-project/locations/us-central1/clusters/vision/nodePools/l4-shared"

    mig = pools["a100-mig"]
    assert mig["gpu_sharing"] == {"strategy": "mig", "mig_partition": "1g.5gb"}
    assert mig["gpu_driver"] == {"management": "user-managed", "setting": "INSTALLATION_DISABLED"}
    assert pools["default-pool"]["gpu"] is False


# ── AKS ──────────────────────────────────────────────────────────────────────


def _aks_module(clusters: list[dict[str, Any]]) -> dict[str, Any]:
    class _ManagedClusters:
        def list(self) -> list[Any]:
            return _ns(clusters)

    class _Client:
        def __init__(self, _credential: Any, _subscription: str) -> None:
            self.managed_clusters = _ManagedClusters()

    module = types.ModuleType("azure.mgmt.containerservice")
    module.ContainerServiceClient = _Client  # type: ignore[attr-defined]
    azure = types.ModuleType("azure")
    mgmt = types.ModuleType("azure.mgmt")
    return {"azure": azure, "azure.mgmt": mgmt, "azure.mgmt.containerservice": module}


def test_aks_agent_pools_capture_gpu_vm_sizes_mig_and_driver_opt_out() -> None:
    from agent_bom.cloud.azure_inv.compute_storage import _discover_aks_clusters

    warnings: list[str] = []
    with patch_sdk_namespace(_aks_module(_load("aks_managed_clusters.json")), "azure"):
        (cluster,) = _discover_aks_clusters(None, "00000000-0000-0000-0000-000000000000", warnings=warnings)
    assert warnings == []
    pools = {pool["name"]: pool for pool in cluster["node_pools"]}
    a100 = pools["gpunc"]
    assert (a100["gpu"], a100["gpu_vendor"], a100["accelerator_type"]) == (True, "nvidia", "A100")
    assert a100["gpu_sharing"] == {"strategy": "mig", "mig_partition": "MIG2g"}
    assert a100["gpu_driver"]["management"] == "provider-managed"
    assert a100["node_public_ip"] is True
    assert a100["pool_id"].endswith("/managedClusters/aks-ml/agentPools/gpunc")
    t4 = pools["gput4"]
    assert t4["gpu_driver"] == {"management": "user-managed", "setting": "None"}
    assert t4["taints"] == [{"key": "sku", "value": "gpu", "effect": "NoSchedule"}]
    assert pools["system"]["gpu"] is False


def test_pool_node_id_is_case_insensitive_only_for_azure() -> None:
    assert gpu_pool_node_id("azure", "/subscriptions/S/RG", "p") == gpu_pool_node_id("azure", "/subscriptions/s/rg", "p")
    assert gpu_pool_node_id("gcp", "projects/P/x", "p") != gpu_pool_node_id("gcp", "projects/p/x", "p")
