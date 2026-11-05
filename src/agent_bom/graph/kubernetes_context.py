"""Deployment and endpoint context using exact Kubernetes object references."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType as E
from agent_bom.graph.types import RelationshipType as R

if TYPE_CHECKING:
    from agent_bom.graph.kubernetes_scope import KubernetesScope as _Scope


def _object_id(scope: _Scope, ref: Mapping[str, Any], graph: UnifiedGraph) -> str:
    if ref["kind"] == "Pod":
        legacy_id = f"container:k8s:pod:{ref['uid']}"
        legacy = graph.nodes.get(legacy_id)
        if legacy and legacy.attributes.get("cluster") == scope.cluster and legacy.attributes.get("namespace") == ref["namespace"]:
            return legacy_id
        # Cluster-qualified, unlike legacy discovery IDs. Never join contexts by pod name.
        return f"container:k8s:runtime-pod:{scope.key(ref['namespace'], ref['uid'])}"
    return scope.ids()["workload"](ref)


def project_context(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any], project_image: Callable[..., None]) -> None:
    records = [*inventory.get("controller_context", []), *inventory.get("pod_context", [])]
    by_ref = {(r["kind"], r["namespace"], r["name"], r["uid"]): r for r in records if r.get("uid")}
    for ref in by_ref.values():
        node_id = _object_id(scope, ref, graph)
        if node_id not in graph.nodes:
            graph.add_node(
                scope.node(
                    node_id,
                    E.CONTAINER,
                    f"{ref['kind'].lower()}: {ref['namespace']}/{ref['name']}",
                    container_kind="pod" if ref["kind"] == "Pod" else "workload",
                    resource_type=ref["kind"].lower(),
                    kubernetes_kind=ref["kind"],
                    kubernetes_name=ref["name"],
                    kubernetes_uid=ref["uid"],
                    namespace=ref["namespace"],
                )
            )
    for ref in by_ref.values():
        node_id = _object_id(scope, ref, graph)
        owner = ref.get("owner")
        if owner and tuple(owner[k] for k in ("kind", "namespace", "name", "uid")) in by_ref:
            parent = _object_id(scope, owner, graph)
            graph.add_edge(
                UnifiedEdge(
                    source=parent,
                    target=node_id,
                    relationship=R.CONTAINS,
                    traversable=False,
                    evidence=scope.evidence("kubernetes_owner_reference", owner_uid=owner["uid"], child_uid=ref["uid"]),
                )
            )
        for container in ref.get("containers", []):
            runtime_id = f"{node_id}/container/{container['name']}"
            graph.add_node(
                scope.node(
                    runtime_id,
                    E.CONTAINER,
                    container["name"],
                    container_kind="runtime",
                    resource_type="kubernetes_container",
                    container_name=container["name"],
                    pod_uid=ref["uid"],
                    namespace=ref["namespace"],
                    image_ref=container["image"],
                )
            )
            if container.get("image"):
                project_image(graph, scope, runtime_id, container)
            graph.add_edge(
                UnifiedEdge(
                    source=node_id,
                    target=runtime_id,
                    relationship=R.CONTAINS,
                    traversable=False,
                    evidence=scope.evidence("kubernetes_pod_container", pod_uid=ref["uid"]),
                )
            )
    _project_routes(graph, scope, inventory)


def _project_routes(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any]) -> None:
    services = {}
    for service in inventory.get("services", []):
        if not service.get("uid"):
            continue
        node_id = f"cloud_resource:k8s:service:{scope.key(service['namespace'], service['uid'])}"
        services[service["uid"]] = node_id
        graph.add_node(
            scope.node(
                node_id,
                E.CLOUD_RESOURCE,
                f"service: {service['namespace']}/{service['name']}",
                resource_type="application_endpoint",
                kubernetes_kind="Service",
                kubernetes_uid=service["uid"],
                namespace=service["namespace"],
                service_type=service["type"],
                ports=service["ports"],
                network_reachability="unknown",
            )
        )
    _project_ingresses(graph, scope, inventory, services)
    for route in inventory.get("endpoint_routes", []):
        source, target = services.get(route["service"]["uid"]), _object_id(scope, route["pod"], graph)
        if source and target in graph.nodes:
            graph.add_edge(
                UnifiedEdge(
                    source=source,
                    target=target,
                    relationship=R.EXPOSED_TO,
                    traversable=False,
                    evidence=scope.evidence(
                        "kubernetes_endpoint_slice",
                        endpoint_slice_uid=route["slice"]["uid"],
                        service_uid=route["service"]["uid"],
                        pod_uid=route["pod"]["uid"],
                        ports=route["ports"],
                        network_reachability="unknown",
                        missing_evidence=["effective_route_and_rule_evaluation", "observed_traffic"],
                    ),
                )
            )


def _project_ingresses(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any], services: dict[str, str]) -> None:
    for ingress in inventory.get("ingresses", []):
        if not ingress.get("uid"):
            continue
        node_id = f"api_gateway:k8s:ingress:{scope.key(ingress['namespace'], ingress['uid'])}"
        graph.add_node(
            scope.node(
                node_id,
                E.API_GATEWAY,
                f"ingress: {ingress['namespace']}/{ingress['name']}",
                resource_type="application_endpoint",
                kubernetes_kind="Ingress",
                kubernetes_uid=ingress["uid"],
                namespace=ingress["namespace"],
                network_reachability="unknown",
            )
        )
        for backend in ingress["backends"]:
            target = services.get(backend["service"]["uid"])
            if target:
                graph.add_edge(
                    UnifiedEdge(
                        source=node_id,
                        target=target,
                        relationship=R.EXPOSED_TO,
                        traversable=False,
                        evidence=scope.evidence(
                            "kubernetes_ingress_backend",
                            ingress_uid=ingress["uid"],
                            service_uid=backend["service"]["uid"],
                            service_port=backend["port"],
                            network_reachability="unknown",
                        ),
                    )
                )
