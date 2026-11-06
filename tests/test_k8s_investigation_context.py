"""Recorded Kubernetes routing and deployment context, never inferred exposure."""

from copy import deepcopy

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.kubernetes_projection import project_kubernetes_inventory
from agent_bom.kubernetes.inventory import build_k8s_inventory


def objects():
    deployment = {
        "kind": "Deployment",
        "metadata": {"namespace": "shop", "name": "web", "uid": "dep-1"},
        "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "example.test/web:1"}]}}},
    }
    pod = {
        "kind": "Pod",
        "metadata": {
            "namespace": "shop",
            "name": "web-a",
            "uid": "pod-1",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "uid": "dep-1", "controller": True}],
        },
        "spec": {"containers": [{"name": "app", "image": "example.test/web:1"}]},
    }
    service = {
        "kind": "Service",
        "metadata": {"namespace": "shop", "name": "web", "uid": "svc-1"},
        "spec": {"type": "LoadBalancer", "ports": [{"port": 443, "targetPort": 8080}]},
        "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.7"}]}},
    }
    endpoints = {
        "kind": "EndpointSlice",
        "metadata": {
            "namespace": "shop",
            "name": "web-1",
            "uid": "slice-1",
            "labels": {"kubernetes.io/service-name": "web"},
            "ownerReferences": [{"kind": "Service", "name": "web", "uid": "svc-1"}],
        },
        "ports": [{"port": 8080, "protocol": "TCP"}],
        "endpoints": [{"conditions": {"ready": True}, "targetRef": {"kind": "Pod", "namespace": "shop", "name": "web-a", "uid": "pod-1"}}],
    }
    return [deployment, pod, service, endpoints]


def project(items):
    inv = build_k8s_inventory(items, source="live", cluster="cluster-a")
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    project_kubernetes_inventory(graph, {"inventories": [inv]})
    return inv, graph


def test_pods_and_runtime_containers_survive_controller_grouping():
    inv, graph = project(objects())
    assert len(inv.get("pod_context", [])) == 1
    pod = next(n for n in graph.nodes.values() if n.attributes.get("kubernetes_uid") == "pod-1")
    deployment = next(n for n in graph.nodes.values() if n.attributes.get("kubernetes_uid") == "dep-1")
    assert any(e.source == deployment.id and e.target == pod.id and e.evidence.get("owner_uid") == "dep-1" for e in graph.edges)
    assert any(n.attributes.get("container_kind") == "runtime" and n.attributes.get("pod_uid") == "pod-1" for n in graph.nodes.values())


def test_recreated_same_name_owner_is_not_joined():
    items = objects()
    items[0]["metadata"]["uid"] = "replacement"
    inv, _ = project(items)
    assert next(w for w in inv["workloads"] if w["kind"] == "Deployment")["pod_uids"] == []


def test_endpoint_slice_routes_only_exact_service_and_ready_pod_uids():
    _, graph = project(objects())
    routes = [e for e in graph.edges if e.evidence.get("basis") == "kubernetes_endpoint_slice"]
    assert len(routes) == 1
    assert routes[0].traversable is False
    assert routes[0].evidence["network_reachability"] == "unknown"
    assert not any(n.label == "Internet" for n in graph.nodes.values()), "LB address alone is not ingress proof"
    for mutation in ("pod_uid", "service_uid", "namespace", "not_ready"):
        items = deepcopy(objects())
        endpoint = items[3]["endpoints"][0]
        if mutation == "pod_uid":
            endpoint["targetRef"]["uid"] = "replacement"
        if mutation == "service_uid":
            items[3]["metadata"]["ownerReferences"][0]["uid"] = "replacement"
        if mutation == "namespace":
            endpoint["targetRef"]["namespace"] = "other"
        if mutation == "not_ready":
            endpoint["conditions"]["ready"] = False
        _, invalid = project(items)
        assert not any(e.evidence.get("basis") == "kubernetes_endpoint_slice" for e in invalid.edges), mutation


def test_ingress_backend_is_a_namespaced_configured_service_reference():
    items = objects()
    items.append(
        {
            "kind": "Ingress",
            "metadata": {"name": "web", "namespace": "shop", "uid": "ing-1"},
            "spec": {"rules": [{"http": {"paths": [{"backend": {"service": {"name": "web", "port": {"number": 443}}}}]}}]},
        }
    )
    _, graph = project(items)
    links = [e for e in graph.edges if e.evidence.get("basis") == "kubernetes_ingress_backend"]
    assert len(links) == 1
    assert not links[0].traversable
    assert graph.nodes[links[0].source].attributes["kubernetes_uid"] == "ing-1"
    items[-1]["metadata"]["namespace"] = "other"
    _, other = project(items)
    assert not any(e.evidence.get("basis") == "kubernetes_ingress_backend" for e in other.edges)


def test_runtime_context_is_cluster_scoped_and_excludes_environment_values():
    items = objects()
    items[1]["spec"]["containers"][0]["env"] = [{"name": "PRIVATE_VALUE", "value": "private-fixture-value"}]
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    inventories = [build_k8s_inventory(items, source="live", cluster=cluster) for cluster in ("cluster-a", "cluster-b")]
    project_kubernetes_inventory(graph, {"inventories": inventories})
    pods = [n for n in graph.nodes.values() if n.attributes.get("kubernetes_uid") == "pod-1"]
    assert len(pods) == 2
    routes = [e for e in graph.edges if e.evidence.get("basis") == "kubernetes_endpoint_slice"]
    assert len(routes) == 2
    for route in routes:
        assert graph.nodes[route.source].attributes["cluster"] == graph.nodes[route.target].attributes["cluster"]
    assert "private-fixture-value" not in str(inventories)
    assert "PRIVATE_VALUE" not in str(inventories)


def test_standalone_pod_context_reuses_the_existing_workload_asset():
    items = objects()
    items[1]["metadata"].pop("ownerReferences")
    _, graph = project(items)
    pods = [n for n in graph.nodes.values() if n.attributes.get("kubernetes_uid") == "pod-1"]
    assert len(pods) == 1
    route = next(e for e in graph.edges if e.evidence.get("basis") == "kubernetes_endpoint_slice")
    assert route.target == pods[0].id
    assert any(e.source == pods[0].id and graph.nodes[e.target].attributes.get("container_kind") == "runtime" for e in graph.edges)


def test_malformed_optional_routing_records_do_not_create_links_or_abort_inventory():
    items = objects()
    items[3]["endpoints"] = [None, "invalid", {"targetRef": "invalid", "conditions": "invalid"}]
    items.append(
        {
            "kind": "Ingress",
            "metadata": {"name": "bad", "namespace": "shop", "uid": "bad-1"},
            "spec": {"rules": [None, {"http": {"paths": [None, {"backend": "invalid"}]}}]},
        }
    )
    items.append({"kind": "Service", "metadata": "invalid", "spec": "invalid"})
    inv, graph = project(items)
    assert inv["pod_context"][0]["uid"] == "pod-1"
    assert not any(e.evidence.get("basis") in {"kubernetes_endpoint_slice", "kubernetes_ingress_backend"} for e in graph.edges)


def test_endpoint_slice_treats_an_unset_ready_condition_as_ready():
    items = objects()
    del items[3]["endpoints"][0]["conditions"]["ready"]
    inv, _ = project(items)
    assert [route["pod"]["uid"] for route in inv["endpoint_routes"]] == ["pod-1"]
    del items[3]["endpoints"][0]["conditions"]
    inv, _ = project(items)
    assert [route["pod"]["uid"] for route in inv["endpoint_routes"]] == ["pod-1"]


def test_malformed_routing_records_do_not_reject_the_rest_of_the_report():
    good = build_k8s_inventory(objects(), source="live", cluster="cluster-a")
    bad = deepcopy(good)
    bad["pod_context"] = [*bad["pod_context"], {"uid": "u", "name": "p", "namespace": "n"}, "not-a-record", {"kind": "Pod", "uid": "x"}]
    bad["controller_context"] = None
    bad["services"] = [*bad["services"], {"uid": "s", "namespace": "n"}, 7]
    bad["endpoint_routes"] = [*bad["endpoint_routes"], {"pod": {}}, {"service": {"uid": "svc-1"}}]
    bad["ingresses"] = [{"uid": "i", "namespace": "n", "name": "i"}, {"uid": "j"}]
    graph = UnifiedGraph(scan_id="scan", tenant_id="tenant")
    project_kubernetes_inventory(graph, {"inventories": [bad]})
    assert any(n.attributes.get("kubernetes_uid") == "pod-1" for n in graph.nodes.values())
    assert any(n.attributes.get("kubernetes_uid") == "svc-1" for n in graph.nodes.values())
    assert not any(n.attributes.get("kubernetes_uid") == "s" for n in graph.nodes.values())
