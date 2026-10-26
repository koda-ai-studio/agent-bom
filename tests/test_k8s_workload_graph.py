"""Kubernetes workload graph: namespace → workload → image → package → CVE, workload → SA → RBAC."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.kubernetes.inventory import build_k8s_inventory

_DIGEST = "sha256:" + "c" * 64
_IMAGE = "registry.example.test/shop/web:1.4"
_PINNED = f"registry.example.test/shop/web@{_DIGEST}"
_WORKLOAD = "container:k8s:workload:prod-east/shop/deployment/web"
_IMAGE_NODE = f"container:image:{_PINNED}"
_SA = "service_account:k8s:prod-east/shop/web-sa"
_SECRET = "credential:k8s:secret:prod-east/shop/db-creds"


def _objects(*, automount: bool | None = None) -> list[dict[str, Any]]:
    pod_spec: dict[str, Any] = {
        "serviceAccountName": "web-sa",
        "containers": [
            {
                "name": "app",
                "image": _IMAGE,
                "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "password"}}}],
            }
        ],
    }
    if automount is not None:
        pod_spec["automountServiceAccountToken"] = automount
    return [
        {"kind": "Namespace", "metadata": {"name": "shop", "labels": {}}},
        {"kind": "Deployment", "metadata": {"name": "web", "namespace": "shop", "uid": "dep-1"}, "spec": {"template": {"spec": pod_spec}}},
        {
            "kind": "ReplicaSet",
            "metadata": {"name": "web-1", "namespace": "shop", "ownerReferences": [{"kind": "Deployment", "name": "web"}]},
            "spec": {"template": {"spec": pod_spec}},
        },
        {
            "kind": "Pod",
            "metadata": {
                "name": "web-1-a",
                "namespace": "shop",
                "uid": "pod-a",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-1"}],
            },
            "spec": pod_spec,
            "status": {"phase": "Running", "containerStatuses": [{"name": "app", "imageID": f"docker-pullable://{_PINNED}"}]},
        },
        {"kind": "ServiceAccount", "metadata": {"name": "web-sa", "namespace": "shop"}},
        {
            "kind": "Role",
            "metadata": {"name": "secret-reader", "namespace": "shop"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}],
        },
        {
            "kind": "RoleBinding",
            "metadata": {"name": "web-reads-secrets", "namespace": "shop"},
            "roleRef": {"kind": "Role", "name": "secret-reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}],
        },
    ]


def _image_carrier(ref: str = _PINNED) -> dict[str, Any]:
    return {
        "name": f"image:{ref}",
        "type": "custom",
        "source": "kubernetes-image",
        "metadata": {"inventory_role": "container_image", "image_ref": ref},
        "mcp_servers": [
            {
                "name": ref,
                "surface": "container-image",
                "packages": [
                    {
                        "name": "openssl",
                        "version": "3.0.1",
                        "ecosystem": "deb",
                        "purl": "pkg:deb/debian/openssl@3.0.1",
                        "vulnerabilities": [{"id": "CVE-2099-0001", "severity": "critical", "is_kev": True}],
                    }
                ],
            }
        ],
    }


def _report(inventory: dict[str, Any], agents: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "scan_id": "k8s-graph",
        "scan_sources": ["k8s"],
        "agents": agents if agents is not None else [_image_carrier()],
        "kubernetes_inventory": {"inventories": [inventory]},
    }


def _graph(**kwargs: Any) -> UnifiedGraph:
    inventory = build_k8s_inventory(_objects(**kwargs), source="live", cluster="prod-east")
    return build_unified_graph_from_report(_report(inventory))


def _has_edge(graph: UnifiedGraph, source: str, target: str, rel: RelationshipType) -> bool:
    return any(edge.source == source and edge.target == target and edge.relationship == rel for edge in graph.edges)


def test_workload_image_package_cve_chain_is_real_graph_edges() -> None:
    graph = _graph()

    workload = graph.nodes[_WORKLOAD]
    assert workload.entity_type == EntityType.CONTAINER
    assert workload.attributes["container_kind"] == "workload"
    assert workload.attributes["service_account"] == "web-sa"
    image = graph.nodes[_IMAGE_NODE]
    assert image.attributes["container_kind"] == "image"
    assert image.attributes["image_digest"] == _DIGEST
    package = next(n for n in graph.nodes.values() if n.entity_type == EntityType.PACKAGE and n.label == "openssl@3.0.1")

    assert _has_edge(graph, "cluster:k8s:prod-east", "resource:k8s:namespace:prod-east/shop", RelationshipType.CONTAINS)
    assert _has_edge(graph, "resource:k8s:namespace:prod-east/shop", _WORKLOAD, RelationshipType.CONTAINS)
    assert _has_edge(graph, _WORKLOAD, _IMAGE_NODE, RelationshipType.DEPENDS_ON)
    assert _has_edge(graph, _IMAGE_NODE, package.id, RelationshipType.CONTAINS)
    assert _has_edge(graph, package.id, "vuln:CVE-2099-0001", RelationshipType.VULNERABLE_TO)
    assert not graph.contract_rejections.pairs, graph.contract_rejections.sample


def test_images_are_not_modelled_as_mcp_servers_or_agents() -> None:
    graph = _graph()
    assert not [n for n in graph.nodes.values() if n.entity_type in {EntityType.SERVER, EntityType.AGENT}]
    aliases = graph.nodes[_IMAGE_NODE].attributes["identity"]["aliases"]
    assert any(alias.startswith("agent:") for alias in aliases), "earlier agent ids stay resolvable for diffs"


def test_service_account_rbac_and_secrets_are_attached() -> None:
    graph = _graph()
    role = "role:k8s:prod-east/shop/role/secret-reader"
    assert _has_edge(graph, _WORKLOAD, _SA, RelationshipType.ASSUMES)
    assert _has_edge(graph, _SA, role, RelationshipType.INHERITS)
    assert _has_edge(graph, _SA, "resource:k8s:namespace:prod-east/shop", RelationshipType.HAS_PERMISSION)
    assert _has_edge(graph, _SA, _SECRET, RelationshipType.CAN_ACCESS)
    assert _has_edge(graph, _WORKLOAD, _SECRET, RelationshipType.CAN_ACCESS)
    secret = graph.nodes[_SECRET]
    assert secret.entity_type == EntityType.CREDENTIAL
    assert secret.attributes["value_collected"] is False


def test_attack_paths_run_cve_to_workload_and_workload_through_service_account_to_secret() -> None:
    graph = _graph()
    paths = _derived_attack_paths(graph)

    component = [p for p in paths if p.target == "vuln:CVE-2099-0001" and _WORKLOAD in p.hops]
    assert component, "the CVE path walks image → workload"
    assert component[0].hops[-4:] == [_WORKLOAD, _IMAGE_NODE, component[0].hops[-2], "vuln:CVE-2099-0001"]

    pivot = [p for p in paths if p.source == _WORKLOAD and p.target == _SECRET and _SA in p.hops]
    assert pivot, [p.hops for p in paths]
    assert pivot[0].vuln_ids == ["CVE-2099-0001"]
    assert pivot[0].edges[0] == "assumes"
    assert "act as service account: shop/web-sa" in pivot[0].summary


def test_pivot_analysis_status_is_recorded_and_a_hit_cap_is_labelled(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.graph import workload_pivot_paths

    graph = _graph()
    _derived_attack_paths(graph)
    status = graph.analysis_status["workload_pivot_paths"]
    assert status.status.value == "complete" and status.observed["paths"] >= 1

    monkeypatch.setattr(workload_pivot_paths, "MAX_PATHS", 1)
    capped = _graph()
    _derived_attack_paths(capped)
    limited = capped.analysis_status["workload_pivot_paths"]
    assert limited.status.value == "limited"
    assert "path_cap_reached" in limited.reason_codes


def test_unmounted_token_does_not_start_an_identity_pivot() -> None:
    graph = _graph(automount=False)
    assumes = [e for e in graph.edges if e.source == _WORKLOAD and e.relationship == RelationshipType.ASSUMES]
    assert assumes and assumes[0].traversable is False
    assert not [p for p in _derived_attack_paths(graph) if p.source == _WORKLOAD and _SA in p.hops]


def test_workload_without_scanned_image_has_no_cve_pivot() -> None:
    inventory = build_k8s_inventory(_objects(), source="live", cluster="prod-east")
    graph = build_unified_graph_from_report(_report(inventory, agents=[]))
    assert _has_edge(graph, _WORKLOAD, _IMAGE_NODE, RelationshipType.DEPENDS_ON)
    assert not [p for p in _derived_attack_paths(graph) if p.source == _WORKLOAD]


def test_manifest_and_live_inventories_produce_the_same_shape() -> None:
    manifest = build_k8s_inventory([o for o in _objects() if o["kind"] != "Pod"], source="manifest")
    graph = build_unified_graph_from_report(_report(manifest, agents=[_image_carrier(_IMAGE)]))
    workload = "container:k8s:workload:shop/deployment/web"
    image = f"container:image:{_IMAGE}"
    assert _has_edge(graph, workload, image, RelationshipType.DEPENDS_ON)
    assert _has_edge(graph, workload, "service_account:k8s:shop/web-sa", RelationshipType.ASSUMES)
    tiers = {e.evidence.get("tier") for e in graph.edges if e.source == workload}
    assert tiers == {"static_scan"}
    assert [p for p in _derived_attack_paths(graph) if p.source == workload and p.target == "credential:k8s:secret:shop/db-creds"]


def test_mcp_server_running_in_a_pod_is_hosted_on_its_workload() -> None:
    inventory = build_k8s_inventory(_objects(), source="live", cluster="prod-east")
    agent = {
        "name": "k8s-mcp",
        "type": "custom",
        "source": "kubernetes",
        "mcp_servers": [
            {
                "name": "billing-mcp",
                "surface": "mcp-server",
                "connection_metadata": {"k8s_pod_uid": "pod-a", "k8s_pod": "web-1-a", "k8s_namespace": "shop", "k8s_cluster": "prod-east"},
            }
        ],
    }
    graph = build_unified_graph_from_report(_report(inventory, agents=[agent, _image_carrier()]))
    server = next(n.id for n in graph.nodes.values() if n.entity_type == EntityType.SERVER)
    assert _has_edge(graph, server, "container:k8s:pod:pod-a", RelationshipType.HOSTED_ON)
    assert _has_edge(graph, server, _WORKLOAD, RelationshipType.HOSTED_ON)
    paths = _derived_attack_paths(graph)
    assert [p for p in paths if p.target == "vuln:CVE-2099-0001" and p.hops[:3] == [p.hops[0], server, _WORKLOAD]]


@pytest.mark.parametrize("source", ["image", "image-tar"])
def test_plain_image_scans_project_as_image_nodes(source: str) -> None:
    carrier = _image_carrier("busybox:1.36")
    carrier["source"] = source
    carrier["metadata"] = {}
    graph = build_unified_graph_from_report({"scan_id": "s", "agents": [carrier]})
    assert "container:image:busybox:1.36" in graph.nodes
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVER]


def test_cloud_workload_with_image_surface_keeps_its_agent() -> None:
    carrier = _image_carrier("busybox:1.36")
    carrier["source"] = "aws-ecs"
    carrier["metadata"] = {}
    graph = build_unified_graph_from_report({"scan_id": "s", "agents": [carrier]})
    assert [n for n in graph.nodes.values() if n.entity_type == EntityType.AGENT]
