"""Kubernetes workload inventory → graph: namespace → workload → image, service account → RBAC.

Projects the ``kubernetes_inventory`` report section (see
:mod:`agent_bom.kubernetes.inventory`). Live-cluster and manifest inventories produce
the same node and edge shapes; only the evidence tier differs (``recorded``
for API reads, ``static_scan`` for manifests).

Images are keyed exactly as image scans key them
(:func:`agent_bom.graph.image_projection.image_node_id`), so a workload that
runs a scanned image reaches that image's packages and CVEs. A Secret is a
named credential reference only; no value is ever collected.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.core.image_ref import image_repository
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.image_projection import image_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

E, R = EntityType, RelationshipType
_LIVE_SOURCE, _MANIFEST_SOURCE = "kubernetes", "kubernetes-manifest"


class _Scope:
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


def _edge(
    graph: UnifiedGraph, source: str, target: str, rel: RelationshipType, evidence: dict[str, Any], *, traversable: bool = True
) -> None:
    if source in graph.nodes and target in graph.nodes:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel, evidence=evidence, traversable=traversable))


def _project_namespaces(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any]) -> None:
    ids = scope.ids()
    if ids["cluster"]:
        graph.add_node(scope.node(ids["cluster"], E.CLUSTER, f"cluster: {scope.cluster}", resource_type="kubernetes_cluster"))
    for namespace in inventory.get("namespaces") or []:
        labels = namespace.get("labels") or {}
        ns_id = ids["namespace"](namespace["name"])
        graph.add_node(
            scope.node(
                ns_id,
                E.RESOURCE,
                f"namespace: {namespace['name']}",
                resource_type="namespace",
                kubernetes_kind="Namespace",
                kubernetes_name=namespace["name"],
                namespace=namespace["name"],
                pod_security_enforce=str(labels.get("pod-security.kubernetes.io/enforce") or ""),
                pod_security_labels=dict(labels),
                declared=bool(namespace.get("declared")),
            )
        )
        if ids["cluster"]:
            _edge(graph, ids["cluster"], ns_id, R.CONTAINS, scope.evidence("kubernetes_namespace"))


def _project_image(graph: UnifiedGraph, scope: _Scope, workload_id: str, container: Mapping[str, Any]) -> None:
    ref, digest = str(container.get("image") or ""), str(container.get("image_digest") or "")
    image_id = image_node_id(ref, digest)
    graph.add_node(
        UnifiedNode(
            id=image_id,
            entity_type=E.CONTAINER,
            label=f"image: {ref}",
            attributes={
                "container_kind": "image",
                "resource_type": "container_image",
                "image_ref": ref,
                "image_repository": image_repository(ref),
                "image_digest": digest,
            },
            data_sources=[scope.source],
            dimensions=NodeDimensions(surface="container-image"),
        )
    )
    _edge(
        graph, workload_id, image_id, R.DEPENDS_ON, scope.evidence("kubernetes_container_image", container=str(container.get("name") or ""))
    )


def _project_workload(graph: UnifiedGraph, scope: _Scope, workload: Mapping[str, Any]) -> str:
    ids = scope.ids()
    workload_id = ids["workload"](workload)
    graph.add_node(
        scope.node(
            workload_id,
            E.CONTAINER,
            f"{workload['kind'].lower()}: {workload['namespace']}/{workload['name']}",
            container_kind="workload",
            resource_type=workload["kind"].lower(),
            kubernetes_kind=workload["kind"],
            kubernetes_name=workload["name"],
            kubernetes_uid=str(workload.get("uid") or ""),
            namespace=workload["namespace"],
            service_account=workload["service_account"],
            token_mounted=bool(workload.get("token_mounted")),
            host_network=bool(workload.get("host_network")),
            privileged=bool(workload.get("privileged")),
            pod_count=len(workload.get("pod_uids") or []),
            secret_ref_count=len(workload.get("secret_refs") or []),
        )
    )
    _edge(graph, ids["namespace"](workload["namespace"]), workload_id, R.CONTAINS, scope.evidence("kubernetes_namespace_member"))
    for container in workload.get("containers") or []:
        if container.get("image"):
            _project_image(graph, scope, workload_id, container)
    sa_id = ids["service_account"](workload["namespace"], workload["service_account"])
    _edge(
        graph,
        workload_id,
        sa_id,
        R.ASSUMES,
        scope.evidence("kubernetes_service_account", token_mounted=bool(workload.get("token_mounted"))),
        traversable=bool(workload.get("token_mounted")),
    )
    for ref in workload.get("secret_refs") or []:
        secret_id = _secret_node(graph, scope, workload["namespace"], ref["name"])
        _edge(graph, workload_id, secret_id, R.CAN_ACCESS, scope.evidence("kubernetes_secret_reference", via=ref["via"]))
    return workload_id


def _secret_node(graph: UnifiedGraph, scope: _Scope, namespace: str, name: str) -> str:
    secret_id = scope.ids()["secret"](namespace, name)
    graph.add_node(
        scope.node(
            secret_id,
            E.CREDENTIAL,
            f"secret: {namespace}/{name}",
            credential_kind="kubernetes_secret",
            kubernetes_kind="Secret",
            kubernetes_name=name,
            namespace=namespace,
            value_collected=False,
        )
    )
    return secret_id


def _project_service_accounts(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any]) -> None:
    ids = scope.ids()
    for account in inventory.get("service_accounts") or []:
        sa_id = ids["service_account"](account["namespace"], account["name"])
        graph.add_node(
            scope.node(
                sa_id,
                E.SERVICE_ACCOUNT,
                f"service account: {account['namespace']}/{account['name']}",
                kubernetes_kind="ServiceAccount",
                kubernetes_name=account["name"],
                namespace=account["namespace"],
                automount_token=account.get("automount_token"),
                declared=bool(account.get("declared")),
            )
        )
        _edge(graph, ids["namespace"](account["namespace"]), sa_id, R.CONTAINS, scope.evidence("kubernetes_namespace_member"))


def _grant_targets(scope: _Scope, grant: Mapping[str, Any], namespaces: list[str]) -> list[str]:
    ids = scope.ids()
    if grant["scope"] != "cluster":
        return [ids["namespace"](grant["scope"])]
    return [ids["cluster"]] if ids["cluster"] else [ids["namespace"](ns) for ns in namespaces]


def _granted_secrets(graph: UnifiedGraph, scope: _Scope, grant: Mapping[str, Any], known: Iterable[tuple[str, str]]) -> list[str]:
    access = grant.get("secrets") or {}
    in_scope = [(ns, name) for ns, name in known if grant["scope"] == "cluster" or ns == grant["scope"]]
    if access.get("access") == "all":
        return [_secret_node(graph, scope, ns, name) for ns, name in in_scope]
    if access.get("access") == "named":
        namespaces = sorted({ns for ns, _ in in_scope}) if grant["scope"] == "cluster" else [grant["scope"]]
        return [_secret_node(graph, scope, ns, name) for ns in namespaces for name in access.get("names") or []]
    return []


def _rule_summary(grant: Mapping[str, Any]) -> list[str]:
    return [f"{','.join(rule['verbs'])} {','.join(rule['resources'])}" for rule in grant.get("rules") or []][:16]


def _project_grants(graph: UnifiedGraph, scope: _Scope, inventory: Mapping[str, Any]) -> None:
    ids = scope.ids()
    namespaces = [ns["name"] for ns in inventory.get("namespaces") or []]
    known_secrets = sorted({(w["namespace"], ref["name"]) for w in inventory.get("workloads") or [] for ref in w.get("secret_refs") or []})
    for grant in inventory.get("rbac_grants") or []:
        account = grant["service_account"]
        sa_id = ids["service_account"](account["namespace"], account["name"])
        if sa_id not in graph.nodes:
            continue
        role, binding = grant["role"], grant["binding"]
        role_id = ids["role"](role["kind"], binding["namespace"] if role["kind"] == "Role" else "", role["name"])
        graph.add_node(
            scope.node(role_id, E.ROLE, f"{role['kind']}: {role['name']}", kubernetes_kind=role["kind"], kubernetes_name=role["name"])
        )
        basis = {"binding": f"{binding['kind']}/{binding['name']}", "role": f"{role['kind']}/{role['name']}", "grant_scope": grant["scope"]}
        _edge(graph, sa_id, role_id, R.INHERITS, scope.evidence("kubernetes_rbac_binding", **basis))
        permission = scope.evidence(
            "kubernetes_rbac_binding",
            **basis,
            role_resolved=bool(grant.get("role_resolved")),
            role_source=grant.get("role_source"),
            wildcard=bool(grant.get("wildcard")),
            secret_access=(grant.get("secrets") or {}).get("access"),
            rules=_rule_summary(grant),
        )
        for target in _grant_targets(scope, grant, namespaces):
            _edge(graph, sa_id, target, R.HAS_PERMISSION, dict(permission))
        for secret_id in _granted_secrets(graph, scope, grant, known_secrets):
            _edge(graph, sa_id, secret_id, R.CAN_ACCESS, scope.evidence("kubernetes_rbac_secret_read", **basis))


def _pod_hosted_servers(graph: UnifiedGraph) -> dict[str, list[str]]:
    hosted: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.relationship == R.HOSTED_ON and edge.target.startswith("container:k8s:pod:"):
            hosted.setdefault(edge.target, []).append(edge.source)
    return hosted


def _link_hosted_servers(
    graph: UnifiedGraph, scope: _Scope, workload: Mapping[str, Any], workload_id: str, hosted: dict[str, list[str]]
) -> None:
    """An MCP server discovered in a pod runs in that pod's workload."""
    for uid in workload.get("pod_uids") or []:
        pod_id = f"container:k8s:pod:{uid}"
        if pod_id not in graph.nodes:
            continue
        graph.nodes[pod_id].attributes["kubernetes_workload"] = workload_id
        for server_id in hosted.get(pod_id, []):
            _edge(graph, server_id, workload_id, R.HOSTED_ON, scope.evidence("kubernetes_pod_owner", pod_uid=uid))


def project_kubernetes_inventory(graph: UnifiedGraph, section: Any) -> None:
    """Project every inventory in the ``kubernetes_inventory`` report section."""
    if not isinstance(section, Mapping):
        return
    inventories = [inv for inv in section.get("inventories") or [] if isinstance(inv, Mapping)]
    hosted = _pod_hosted_servers(graph) if any(w.get("pod_uids") for inv in inventories for w in inv.get("workloads") or []) else {}
    for inventory in inventories:
        scope = _Scope(inventory)
        _project_namespaces(graph, scope, inventory)
        _project_service_accounts(graph, scope, inventory)
        for workload in inventory.get("workloads") or []:
            workload_id = _project_workload(graph, scope, workload)
            _link_hosted_servers(graph, scope, workload, workload_id, hosted)
        _project_grants(graph, scope, inventory)
