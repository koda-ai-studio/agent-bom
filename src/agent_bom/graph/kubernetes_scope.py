"""Namespaced identifiers and evidence for Kubernetes graph projections."""

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType

_LIVE_SOURCE, _MANIFEST_SOURCE = "kubernetes", "kubernetes-manifest"


class KubernetesScope:
    def __init__(self, inventory: Mapping[str, Any]) -> None:
        self.cluster = str(inventory.get("cluster") or "")
        self.live = inventory.get("source") == "live"
        self.source = _LIVE_SOURCE if self.live else _MANIFEST_SOURCE
        self.tier = "recorded" if self.live else "static_scan"
        self.dims = NodeDimensions(surface="kubernetes")

    def key(self, *parts: str) -> str:
        return "/".join((self.cluster, *parts) if self.cluster else parts)

    def evidence(self, basis: str, **extra: Any) -> dict[str, Any]:
        return edge_evidence(self.source, self.tier, basis, **extra)

    def node(self, node_id: str, entity: EntityType, label: str, **attributes: Any) -> UnifiedNode:
        return UnifiedNode(
            id=node_id,
            entity_type=entity,
            label=label,
            attributes={"cluster": self.cluster, **attributes},
            data_sources=[self.source],
            dimensions=self.dims,
        )

    def ids(self) -> dict[str, Any]:
        return {
            "cluster": f"cluster:k8s:{self.cluster}" if self.cluster else "",
            "namespace": lambda ns: f"resource:k8s:namespace:{self.key(ns)}",
            "workload": lambda w: f"container:k8s:workload:{self.key(w['namespace'], w['kind'].lower(), w['name'])}",
            "service_account": lambda ns, name: f"service_account:k8s:{self.key(ns, name)}",
            "role": lambda kind, ns, name: f"role:k8s:{self.key(ns or '_cluster', kind.lower(), name)}",
            "secret": lambda ns, name: f"credential:k8s:secret:{self.key(ns, name)}",
        }
