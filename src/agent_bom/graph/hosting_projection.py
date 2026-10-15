"""Where a workload runs: ``HOSTED_ON`` edges from recorded hosting evidence.

A Kubernetes-discovered MCP server records its pod uid and the provider id of
the node the pod is scheduled on. The server is hosted on the pod, and the pod
on the node's VM, so an attack path can walk from the agent through the server
and its pod to a CVE on the VM underneath. Only identifiers the source recorded
are used; nothing is inferred from names.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

SOURCE = "kubernetes"
_AWS_PROVIDER_ID = re.compile(r"^aws:///(?P<zone>[a-z]{2}-[a-z]+-\d[a-z])/(?P<instance>i-[0-9a-f]{8,17})$")
_AZURE_PROVIDER_ID = re.compile(r"^azure://(?P<arm>/subscriptions/.+)$", re.IGNORECASE)
_GCE_PROVIDER_ID = re.compile(r"^gce://(?P<project>[^/]+)/(?P<zone>[^/]+)/(?P<name>[^/]+)$")


def provider_id_host(provider_id: str) -> UnifiedNode | None:
    """The VM a Kubernetes node ``spec.providerID`` names, keyed as inventory keys it."""
    aws = _AWS_PROVIDER_ID.match(provider_id)
    if aws:
        instance, zone = aws.group("instance"), aws.group("zone")
        attrs = {"resource_id": instance, "region": zone[:-1], "location": zone[:-1], "cloud_provider": "aws", "cloud_service": "ec2"}
        return _host(f"cloud_resource:aws:ec2:instance:{instance}", instance, "aws", attrs)
    azure = _AZURE_PROVIDER_ID.match(provider_id)
    if azure:
        arm = azure.group("arm").rstrip("/")
        attrs = {"resource_id": arm, "cloud_provider": "azure"}
        return _host(f"cloud_resource:azure:compute:virtual_machine:{arm.casefold()}", arm.rsplit("/", 1)[-1], "azure", attrs)
    gce = _GCE_PROVIDER_ID.match(provider_id)
    if gce:
        link = f"projects/{gce.group('project')}/zones/{gce.group('zone')}/instances/{gce.group('name')}"
        attrs = {"self_link": link, "project_id": gce.group("project"), "location": gce.group("zone"), "cloud_provider": "gcp"}
        return _host(f"cloud_resource:gcp:compute:instance:{link}", gce.group("name"), "gcp", attrs)
    return None


def _host(node_id: str, name: str, provider: str, attrs: dict[str, Any]) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=f"vm: {name}",
        attributes={"resource_name": name, "resource_type": "instance", **attrs},
        data_sources=[SOURCE],
        dimensions=NodeDimensions(cloud_provider=provider, surface="compute"),
    )


def _hosted_on(graph: UnifiedGraph, workload: str, host: str, data_source: str, **extra: str) -> None:
    graph.add_edge(
        UnifiedEdge(
            source=workload,
            target=host,
            relationship=RelationshipType.HOSTED_ON,
            evidence=edge_evidence(data_source or SOURCE, "recorded", "kubernetes_scheduling", **extra),
        )
    )


def project_server_hosting(graph: UnifiedGraph, server_id: str, server: Mapping[str, Any], data_source: str) -> None:
    """Server → pod → node VM, from the pod uid and node provider id discovery recorded."""
    metadata = server.get("connection_metadata")
    if not isinstance(metadata, Mapping):
        return
    pod_uid = str(metadata.get("k8s_pod_uid") or "").strip()
    if not pod_uid:
        return
    namespace, pod_name = str(metadata.get("k8s_namespace") or ""), str(metadata.get("k8s_pod") or "")
    pod_id = f"container:k8s:pod:{pod_uid}"
    graph.add_node(
        UnifiedNode(
            id=pod_id,
            entity_type=EntityType.CONTAINER,
            label=f"pod: {namespace}/{pod_name}" if pod_name else f"pod: {pod_uid}",
            attributes={
                "kubernetes_uid": pod_uid,
                "kubernetes_kind": "Pod",
                "kubernetes_name": pod_name,
                "namespace": namespace,
                "cluster": str(metadata.get("k8s_cluster") or ""),
                "kubernetes_node": str(metadata.get("k8s_node") or ""),
            },
            data_sources=[data_source or SOURCE],
            dimensions=NodeDimensions(surface="kubernetes"),
        )
    )
    _hosted_on(graph, server_id, pod_id, data_source, pod_uid=pod_uid)
    host = provider_id_host(str(metadata.get("k8s_node_provider_id") or "").strip())
    if host is not None:
        graph.add_node(host)
        _hosted_on(graph, pod_id, host.id, data_source, node=str(metadata.get("k8s_node") or ""))
