"""Read-only live collection of the Kubernetes workload inventory.

Lists workloads, pods, service accounts and RBAC through the bounded
:class:`~agent_bom.k8s_transport.K8sReadTransport` (in-cluster API or a
kubectl context). Every list records collector evidence, so a forbidden or
failed read is visible as ``unevaluable`` / ``failed`` instead of an empty,
clean-looking inventory. Secrets are never listed.
"""

from __future__ import annotations

from typing import Any

from agent_bom.core.image_ref import image_key
from agent_bom.k8s_transport import CLUSTER_RESOURCES, K8sReadTransport, K8sTransportError
from agent_bom.kubernetes.inventory import build_k8s_inventory
from agent_bom.kubernetes.posture_models import CollectorState, K8sCollectorEvidence

INVENTORY_RESOURCES: dict[str, str] = {
    "namespaces": "Namespace",
    "pods": "Pod",
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "replicasets": "ReplicaSet",
    "jobs": "Job",
    "cronjobs": "CronJob",
    "serviceaccounts": "ServiceAccount",
    "roles": "Role",
    "rolebindings": "RoleBinding",
    "clusterroles": "ClusterRole",
    "clusterrolebindings": "ClusterRoleBinding",
}
# Without these the workload → image path cannot be built at all.
_REQUIRED = frozenset({"pods"})


def _evidence(resource: str, transport: str, exc: K8sTransportError | None = None, read: Any = None) -> K8sCollectorEvidence:
    if exc is not None:
        state = CollectorState.UNEVALUABLE if exc.status_code in {401, 403, 404} else CollectorState.FAILED
        return K8sCollectorEvidence(collector_id=resource, state=state, message=str(exc), transport=transport)
    return K8sCollectorEvidence(
        collector_id=resource,
        state=CollectorState.EXECUTED,
        object_count=read.object_count,
        pages=read.pages,
        truncated=read.truncated,
        message="collection reached its configured bound" if read.truncated else "",
        transport=transport,
    )


def _collection_status(collectors: list[K8sCollectorEvidence]) -> str:
    by_id = {collector.collector_id: collector for collector in collectors}
    if any(by_id[resource].state is not CollectorState.EXECUTED for resource in _REQUIRED if resource in by_id):
        return "failed"
    if any(collector.state is not CollectorState.EXECUTED or collector.truncated for collector in collectors):
        return "partial"
    return "complete"


def collect_live_k8s_inventory(
    transport: K8sReadTransport,
    *,
    namespace: str = "default",
    all_namespaces: bool = False,
    cluster: str = "",
) -> dict[str, Any]:
    """Collect and normalize the live workload inventory; ``collection`` records completeness."""
    transport_name = str(getattr(transport, "name", "") or "")
    objects: list[dict[str, Any]] = []
    collectors: list[K8sCollectorEvidence] = []
    for resource, kind in INVENTORY_RESOURCES.items():
        scoped = None if resource in CLUSTER_RESOURCES else namespace
        try:
            read = transport.list_resource(resource, namespace=scoped, all_namespaces=all_namespaces)
        except K8sTransportError as exc:
            collectors.append(_evidence(resource, transport_name, exc=exc))
            continue
        collectors.append(_evidence(resource, transport_name, read=read))
        for item in read.data.get("items") or []:
            if not isinstance(item, dict):
                continue
            if kind == "Namespace" and not all_namespaces and (item.get("metadata") or {}).get("name") != namespace:
                continue
            objects.append({**item, "kind": item.get("kind") or kind})
    inventory = build_k8s_inventory(objects, source="live", cluster=cluster)
    inventory["collection"] = {
        "status": _collection_status(collectors),
        "transport": transport_name,
        "namespace_scope": "all" if all_namespaces else namespace,
        "collectors": [
            {
                "collector_id": c.collector_id,
                "state": c.state.value,
                "object_count": c.object_count,
                "truncated": c.truncated,
                "message": c.message,
            }
            for c in collectors
        ],
    }
    return inventory


def cluster_label(context: str | None, transport_name: str) -> str:
    """A label that keeps two clusters' objects apart; a local name, not a provider identity."""
    if context:
        return context
    return "in-cluster" if transport_name == "in-cluster" else "current-context"


def scan_targets(inventory: dict[str, Any]) -> list[dict[str, str]]:
    """Distinct images to scan: pinned to the running digest when one was recorded."""
    targets: dict[str, dict[str, str]] = {}
    for workload in inventory.get("workloads") or []:
        for container in workload.get("containers") or []:
            image, digest = str(container.get("image") or ""), str(container.get("image_digest") or "")
            if not image:
                continue
            ref = image_key(image, digest)
            targets.setdefault(ref, {"ref": ref, "image": image, "image_digest": digest})
    return [targets[ref] for ref in sorted(targets)]
