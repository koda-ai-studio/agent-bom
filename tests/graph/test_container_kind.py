"""Container nodes say whether they are an image or a running workload."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container_kind import container_kind
from agent_bom.graph.types import EntityType


def test_kind_comes_only_from_recorded_fields() -> None:
    assert container_kind({"resource_type": "container_image"}) == "image"
    assert container_kind({"asset_type": "container_image"}) == "image"
    assert container_kind({"resource_type": "deployment"}) == "workload"
    assert container_kind({"kubernetes_kind": "Pod"}) == "workload"
    assert container_kind({"label": "nginx:1.25 image"}) == ""
    assert container_kind({"container_kind": "image", "resource_type": "deployment"}) == "image"


def test_builder_pod_is_a_workload_and_serving_image_is_an_image() -> None:
    report = {
        "agents": [
            {
                "name": "k8s",
                "type": "custom",
                "source": "kubernetes",
                "mcp_servers": [
                    {
                        "name": "tools/mcp",
                        "url": "http://mcp.tools.svc:8000",
                        "transport": "sse",
                        "connection_metadata": {"k8s_pod_uid": "uid-1", "k8s_pod": "mcp", "k8s_namespace": "tools"},
                    }
                ],
            }
        ],
        "serving_configs": [{"name": "svc", "container_image": "registry.example/model:1"}],
    }
    graph = build_unified_graph_from_report(report)
    containers = {
        node.id: node.attributes.get("container_kind") for node in graph.nodes.values() if node.entity_type == EntityType.CONTAINER
    }

    assert containers["container:k8s:pod:uid-1"] == "workload"
    assert [kind for node_id, kind in containers.items() if node_id.startswith("container:serving-config:")] == ["image"]
