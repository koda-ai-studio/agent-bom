"""Repeated framework imports resolve package identities once per graph build."""

from unittest.mock import patch

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.framework_topology_projection import _add_ai_stack_frameworks
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


@pytest.mark.parametrize("store_backed", [False, True])
def test_repeated_imports_batch_package_lookup(store_backed):
    if store_backed:
        from agent_bom.graph.store_backed import open_store_backed_unified_graph

        graph = open_store_backed_unified_graph(scan_id="batch-test", tenant_id="tenant-one", backend="sqlite", capacity=8, page_size=7)
    else:
        graph = UnifiedGraph(scan_id="batch-test", tenant_id="tenant-one")
    for number in range(43):
        graph.add_node(
            UnifiedNode(id=f"pkg:filler-{number}", entity_type=EntityType.PACKAGE, label=f"filler-{number}@1", attributes={"version": "1"})
        )
    graph.add_node(
        UnifiedNode(
            id="pkg:pinned", entity_type=EntityType.PACKAGE, label="framework@1.2", attributes={"ecosystem": "pypi", "version": "1.2"}
        )
    )
    graph.add_node(
        UnifiedNode(
            id="pkg:other", entity_type=EntityType.PACKAGE, label="framework@2.0", attributes={"ecosystem": "npm", "version": "2.0"}
        )
    )
    data = {"components": [{"type": "agent_framework", "name": "framework", "package": "framework", "ecosystem": "pypi"}] * 40}
    try:
        with (
            patch.object(graph, "nodes_by_type", wraps=graph.nodes_by_type) as mutable_lookup,
            patch.object(graph, "iter_nodes_by_type", wraps=graph.iter_nodes_by_type) as streamed_lookup,
        ):
            _add_ai_stack_frameworks(graph, data, "scan")
        mutable_lookup.assert_not_called()
        streamed_lookup.assert_called_once_with(EntityType.PACKAGE)
        dependencies = [edge for edge in graph.edges if edge.relationship.value == "depends_on"]
        assert len(dependencies) == 1
        assert dependencies[0].target == "pkg:pinned"
        assert not any(node.attributes.get("version") == "latest" for node in graph.nodes.values())
    finally:
        if store_backed:
            graph.close()
