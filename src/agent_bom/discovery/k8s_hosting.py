"""Hosting evidence for Kubernetes-discovered MCP servers: pod uid, node and node provider id."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Optional


def node_provider_ids(kubectl: Callable[..., Optional[dict]]) -> dict[str, str]:
    """``node name -> spec.providerID`` (read-only ``kubectl get nodes``); empty when unreadable."""
    nodes = kubectl("get", "nodes", "-o", "json") or {}
    result: dict[str, str] = {}
    for node in nodes.get("items", []) if isinstance(nodes, dict) else []:
        name = str((node.get("metadata") or {}).get("name") or "")
        provider_id = str((node.get("spec") or {}).get("providerID") or "")
        if name and provider_id:
            result[name] = provider_id
    return result


def pod_hosting_metadata(pod: dict[str, Any], *, cluster: str, provider_ids: dict[str, str]) -> dict[str, str]:
    """The identifiers that place a pod's server on its pod and node VM."""
    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
    node = str(spec.get("nodeName") or "")
    fields = {
        "k8s_pod_uid": str(meta.get("uid") or ""),
        "k8s_pod": str(meta.get("name") or ""),
        "k8s_namespace": str(meta.get("namespace") or ""),
        "k8s_cluster": cluster,
        "k8s_node": node,
        "k8s_node_provider_id": provider_ids.get(node, ""),
    }
    return {key: value for key, value in fields.items() if value}
