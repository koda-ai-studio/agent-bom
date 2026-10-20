"""An attack path always leads somewhere: no path starts and ends on one node.

A single-node risk (an admin-equivalent role, a resource with stacked toxic
factors and nothing it reaches) is a finding on that node, not a path. Served as
a path it read as ``bucket -> bucket · 0 hops`` in the queue and the changes
panel.
"""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _derived_attack_paths, _derived_toxic_combination_paths
from agent_bom.graph.types import EntityType, RelationshipType


class _CapturingStore:
    def __init__(self) -> None:
        self.graphs: list[UnifiedGraph] = []

    def list_snapshots(self, tenant_id: str) -> list[dict]:
        return []

    def save_graph(self, graph: UnifiedGraph) -> None:
        self.graphs.append(graph)


def _self_paths(paths: list[AttackPath]) -> list[AttackPath]:
    return [path for path in paths if path.source == path.target or len(path.hops) < 2]


def test_admin_equivalent_role_is_not_a_self_path() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="role:admin", entity_type=EntityType.ROLE, label="admin", attributes={"admin_equivalent": True}))
    assert _self_paths(_derived_attack_paths(graph)) == []


def test_toxic_resource_without_a_reached_store_is_not_a_self_path() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="cloud:vm", entity_type=EntityType.CLOUD_RESOURCE, label="vm", attributes={"internet_exposed": True}))
    graph.add_node(
        UnifiedNode(
            id="vuln:x",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-X",
            severity="high",
            attributes={"reachability": "likely", "reachability_basis": ["dependency_path"]},
        )
    )
    graph.add_edge(UnifiedEdge(source="cloud:vm", target="vuln:x", relationship=RelationshipType.VULNERABLE_TO))
    assert _derived_toxic_combination_paths(graph) == []
    assert _self_paths(_derived_attack_paths(graph)) == []


def test_a_materialized_self_path_is_not_served() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="ds:b", entity_type=EntityType.DATA_STORE, label="bucket"))
    graph.attack_paths.append(AttackPath(source="ds:b", target="ds:b", hops=["ds:b"], composite_risk=82.0))
    graph.attack_paths.append(AttackPath(source="ds:a", target="ds:b", hops=[], composite_risk=70.0))
    assert _derived_attack_paths(graph) == []


def test_demo_estate_snapshots_hold_no_self_paths() -> None:
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT, seed_showcase_graph_if_empty

    store = _CapturingStore()
    seed_showcase_graph_if_empty(store, tenant_id=SHOWCASE_TENANT)
    assert store.graphs
    for graph in store.graphs:
        assert graph.attack_paths, graph.scan_id
        assert _self_paths(graph.attack_paths) == [], graph.scan_id
