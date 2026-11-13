"""Roll-up containment: nearest parents only, and typed estate containment edges.

A drill-down lists a scope's *direct* children. When a node is recorded under
both a scope and one of that scope's descendants (an environment CONTAINS every
package in it while the image already holds them), listing it at both levels
double-shows it and buries the real children. Descendant sets — and so every
aggregate — must not change; only the redundant direct listing goes.
"""

from __future__ import annotations

import random

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import ROLLUP_SUBTREE_RELATIONSHIP_TYPES, drill_down, rollup_view
from agent_bom.graph.rollup_edges import descendants
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _node(graph: UnifiedGraph, node_id: str, entity_type: EntityType, severity: str = "") -> None:
    graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id, severity=severity))


def _edge(graph: UnifiedGraph, source: str, target: str, rel: RelationshipType = RelationshipType.CONTAINS) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))


def _image_estate() -> UnifiedGraph:
    """env CONTAINS image, image CONTAINS pkg-a; env also CONTAINS pkg-a directly."""
    graph = UnifiedGraph(scan_id="nearest", tenant_id="t1")
    _node(graph, "env:prod", EntityType.ENVIRONMENT)
    _node(graph, "image:web", EntityType.CLOUD_RESOURCE)
    _node(graph, "pkg:a", EntityType.PACKAGE, "high")
    _node(graph, "pkg:b", EntityType.PACKAGE)
    _edge(graph, "env:prod", "image:web")
    _edge(graph, "image:web", "pkg:a")
    _edge(graph, "env:prod", "pkg:a")
    _edge(graph, "env:prod", "pkg:b")
    return graph


def test_drill_down_lists_only_nearest_parent_children() -> None:
    graph = _image_estate()
    view = drill_down(graph, "env:prod")
    ids = [row["id"] for row in view["children"]]
    assert sorted(ids) == ["image:web", "pkg:b"]
    assert view["summary"]["direct_child_count"] == 2
    image = drill_down(graph, "image:web")
    assert [row["id"] for row in image["children"]] == ["pkg:a"]


def test_nearest_parent_keeps_every_descendant_and_aggregate() -> None:
    graph = _image_estate()
    top = rollup_view(graph)["top_level"]
    assert [row["id"] for row in top] == ["env:prod"]
    aggregate = top[0]["aggregate"]
    assert aggregate["descendant_count"] == 3
    assert aggregate["worst_severity"] == "high"


def test_containment_cycle_keeps_its_parents() -> None:
    """Two parents that are each other's ancestor are not redundant; dropping both would orphan the child."""
    graph = UnifiedGraph(scan_id="cycle", tenant_id="t1")
    for node_id in ("dir:a", "dir:b", "file:c"):
        _node(graph, node_id, EntityType.DIRECTORY if node_id.startswith("dir") else EntityType.SOURCE_FILE)
    _edge(graph, "dir:a", "dir:b")
    _edge(graph, "dir:b", "dir:a")
    _edge(graph, "dir:a", "file:c")
    _edge(graph, "dir:b", "file:c")
    listed = {row["id"] for parent in ("dir:a", "dir:b") for row in drill_down(graph, parent)["children"]}
    assert "file:c" in listed


def test_provider_hosts_account_and_account_owns_identity_roll_up() -> None:
    graph = UnifiedGraph(scan_id="estate", tenant_id="t1")
    _node(graph, "provider:aws", EntityType.PROVIDER)
    _node(graph, "account:aws:1", EntityType.ACCOUNT)
    _node(graph, "role:aws:r", EntityType.ROLE, "high")
    _node(graph, "policy:aws:p", EntityType.POLICY)
    _node(graph, "bucket", EntityType.CLOUD_RESOURCE)
    _node(graph, "data_store:bucket", EntityType.DATA_STORE, "critical")
    _edge(graph, "provider:aws", "account:aws:1", RelationshipType.HOSTS)
    _edge(graph, "account:aws:1", "role:aws:r", RelationshipType.OWNS)
    _edge(graph, "account:aws:1", "policy:aws:p", RelationshipType.OWNS)
    _edge(graph, "account:aws:1", "bucket", RelationshipType.CONTAINS)
    _edge(graph, "bucket", "data_store:bucket", RelationshipType.STORES)
    view = rollup_view(graph)
    assert [row["id"] for row in view["top_level"]] == ["provider:aws"]
    assert view["summary"]["orphan_count"] == 0
    assert view["top_level"][0]["aggregate"]["descendant_count"] == 5
    assert view["top_level"][0]["aggregate"]["worst_severity"] == "critical"
    assert [row["id"] for row in drill_down(graph, "bucket")["children"]] == ["data_store:bucket"]
    assert RelationshipType.STORES in ROLLUP_SUBTREE_RELATIONSHIP_TYPES


def test_provider_parents_an_account_only_when_nothing_else_does() -> None:
    """An account already under an organization stays there; the provider must not become an overlapping root."""
    graph = UnifiedGraph(scan_id="overlap", tenant_id="t1")
    _node(graph, "org:corp", EntityType.ORG)
    _node(graph, "provider:aws", EntityType.PROVIDER)
    _node(graph, "account:aws:1", EntityType.ACCOUNT)
    _node(graph, "bucket", EntityType.CLOUD_RESOURCE, "high")
    _edge(graph, "org:corp", "account:aws:1")
    _edge(graph, "provider:aws", "account:aws:1", RelationshipType.HOSTS)
    _edge(graph, "account:aws:1", "bucket")
    view = rollup_view(graph)
    assert [row["id"] for row in view["top_level"] if row["aggregate"]["descendant_count"]] == ["org:corp"]
    assert view["aggregate_count_metadata"]["additive"] is True
    assert drill_down(graph, "provider:aws")["children"] == []


def test_untyped_hosts_and_stores_do_not_parent() -> None:
    """HOSTS from an environment to an agent and STORES from a server are not ownership; they stay out of the tree."""
    graph = UnifiedGraph(scan_id="typed", tenant_id="t1")
    _node(graph, "env:e", EntityType.ENVIRONMENT)
    _node(graph, "agent:x", EntityType.AGENT)
    _node(graph, "server:s", EntityType.SERVER)
    _node(graph, "dataset:d", EntityType.DATASET)
    _edge(graph, "env:e", "agent:x", RelationshipType.HOSTS)
    _edge(graph, "server:s", "dataset:d", RelationshipType.STORES)
    view = rollup_view(graph)
    assert view["summary"]["container_count"] == 0
    assert view["summary"]["orphan_count"] == 4


@pytest.mark.parametrize("seed", range(25))
def test_drill_down_rows_reconcile_with_parent_descendants(seed: int) -> None:
    """Property: drilling any scope yields rows whose subtrees union to exactly the scope's descendants."""
    rng = random.Random(seed)
    graph = UnifiedGraph(scan_id=f"prop-{seed}", tenant_id="t1")
    ids = [f"n{i}" for i in range(40)]
    for node_id in ids:
        _node(graph, node_id, EntityType.ENVIRONMENT if int(node_id[1:]) < 8 else EntityType.PACKAGE, rng.choice(["", "low", "high"]))
    for index in range(1, len(ids)):
        for _ in range(rng.randint(1, 3)):
            parent = rng.randrange(0, index)
            _edge(graph, ids[parent], ids[index])
    view = rollup_view(graph)
    children: dict[str, list[str]] = {}
    for scope in ids:
        rows = drill_down(graph, scope)["children"]
        children[scope] = [row["id"] for row in rows]
        covered: set[str] = set()
        for row in rows:
            covered.add(row["id"])
            covered.update(descendants(row["id"], children_of(graph, row["id"])))
        assert covered == set(descendants(scope, children_of(graph, scope))), scope
        # Rows are disjoint subtrees exactly when the metadata says the counts add up.
        member_total = sum(1 + row["aggregate"]["descendant_count"] for row in rows)
        assert (member_total == len(covered)) == drill_down(graph, scope)["aggregate_count_metadata"]["additive"] or not rows
    total = sum(1 + row["aggregate"]["descendant_count"] for row in view["top_level"])
    assert total >= len(graph.nodes) - view["summary"]["orphan_count"]


def children_of(graph: UnifiedGraph, root: str) -> dict[str, list[str]]:
    """Every recorded CONTAINS edge, before nearest-parent reduction."""
    out: dict[str, list[str]] = {}
    for edge in graph.edges:
        out.setdefault(edge.source, []).append(edge.target)
    return out
