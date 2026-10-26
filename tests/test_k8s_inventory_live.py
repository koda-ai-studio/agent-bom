"""Live workload inventory collection over a recorded read-only transport."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.k8s_transport import K8sReadResult, K8sTransportError, _resource_path
from agent_bom.kubernetes.inventory_live import INVENTORY_RESOURCES, collect_live_k8s_inventory, scan_targets

_DIGEST = "sha256:" + "d" * 64

# API-server list responses omit ``kind`` on items; the collector supplies it.
_RECORDED: dict[str, list[dict[str, Any]]] = {
    "namespaces": [
        {"metadata": {"name": "shop", "labels": {"pod-security.kubernetes.io/enforce": "baseline"}}},
        {"metadata": {"name": "other"}},
    ],
    "pods": [
        {
            "metadata": {
                "name": "web-1-a",
                "namespace": "shop",
                "uid": "pod-a",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-1"}],
            },
            "spec": {"serviceAccountName": "web-sa", "containers": [{"name": "app", "image": "registry.example.test/web:2"}]},
            "status": {"containerStatuses": [{"name": "app", "imageID": f"registry.example.test/web@{_DIGEST}"}]},
        }
    ],
    "deployments": [
        {
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {
                "template": {
                    "spec": {"serviceAccountName": "web-sa", "containers": [{"name": "app", "image": "registry.example.test/web:2"}]}
                }
            },
        }
    ],
    "replicasets": [
        {
            "metadata": {"name": "web-1", "namespace": "shop", "ownerReferences": [{"kind": "Deployment", "name": "web"}]},
            "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "registry.example.test/web:2"}]}}},
        }
    ],
    "serviceaccounts": [{"metadata": {"name": "web-sa", "namespace": "shop"}}],
}


class _Transport:
    name = "fake"

    def __init__(self, denied: frozenset[str] = frozenset(), failed: frozenset[str] = frozenset()) -> None:
        self.denied, self.failed, self.calls = denied, failed, []

    def list_resource(self, resource: str, *, namespace: str | None = None, all_namespaces: bool = False) -> K8sReadResult:
        _resource_path(resource, namespace, all_namespaces)
        self.calls.append((resource, namespace, all_namespaces))
        if resource in self.denied:
            raise K8sTransportError("forbidden", status_code=403)
        if resource in self.failed:
            raise K8sTransportError("timeout", reason="timeout")
        items = _RECORDED.get(resource, [])
        return K8sReadResult(data={"items": items}, object_count=len(items), pages=1, truncated=False)

    def get_kubelet_json(self, *_args: Any, **_kwargs: Any) -> dict:
        raise AssertionError("inventory never reads the kubelet")

    def close(self) -> None:
        return None


def test_live_collection_builds_the_inventory_and_records_complete_collection() -> None:
    transport = _Transport()
    inventory = collect_live_k8s_inventory(transport, namespace="shop", cluster="prod-east")

    assert [(w["kind"], w["name"]) for w in inventory["workloads"]] == [("Deployment", "web")]
    assert inventory["workloads"][0]["containers"][0]["image_digest"] == _DIGEST
    assert inventory["namespaces"] == [{"name": "shop", "labels": {"pod-security.kubernetes.io/enforce": "baseline"}, "declared": True}]
    assert inventory["collection"]["status"] == "complete"
    assert {c["collector_id"] for c in inventory["collection"]["collectors"]} == set(INVENTORY_RESOURCES)
    namespaced = {resource for resource, namespace, _ in transport.calls if namespace == "shop"}
    assert "pods" in namespaced and "namespaces" not in namespaced


def test_secrets_are_never_requested_and_cannot_be() -> None:
    transport = _Transport()
    collect_live_k8s_inventory(transport, all_namespaces=True)
    assert "secrets" not in {resource for resource, _, _ in transport.calls}
    with pytest.raises(K8sTransportError):
        _resource_path("secrets", "shop", False)


def test_forbidden_rbac_reads_make_the_inventory_partial_not_clean() -> None:
    inventory = collect_live_k8s_inventory(_Transport(denied=frozenset({"roles", "clusterrolebindings"})), namespace="shop")
    states = {c["collector_id"]: c["state"] for c in inventory["collection"]["collectors"]}
    assert states["roles"] == "unevaluable"
    assert states["clusterrolebindings"] == "unevaluable"
    assert inventory["collection"]["status"] == "partial"


def test_unreadable_pods_fail_the_collection() -> None:
    inventory = collect_live_k8s_inventory(_Transport(failed=frozenset({"pods"})), namespace="shop")
    assert inventory["collection"]["status"] == "failed"
    assert {c["collector_id"]: c["state"] for c in inventory["collection"]["collectors"]}["pods"] == "failed"


def test_scan_targets_pin_the_running_digest() -> None:
    inventory = collect_live_k8s_inventory(_Transport(), namespace="shop")
    assert scan_targets(inventory) == [
        {"ref": f"registry.example.test/web@{_DIGEST}", "image": "registry.example.test/web:2", "image_digest": _DIGEST}
    ]
