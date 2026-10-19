"""Package -> package DEPENDS_ON edges come from the recorded dependency tree."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.reach_view import REACH_RELATIONSHIP_TYPES
from agent_bom.graph.relationship_specs import TraversalClass, relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType


def _pkg(name: str, version: str, *, direct: bool, parent: str | None = None, depth: int = 0) -> dict:
    return {
        "name": name,
        "version": version,
        "ecosystem": "npm",
        "purl": f"pkg:npm/{name}@{version}",
        "is_direct": direct,
        "parent_package": parent,
        "dependency_depth": depth,
        "vulnerabilities": [],
    }


def _report(packages: list[dict]) -> dict:
    return {
        "agents": [
            {
                "name": "dev",
                "type": "custom",
                "source": "test",
                "mcp_servers": [{"name": "fs", "command": "npx", "args": ["fs"], "packages": packages}],
            }
        ]
    }


def _pkg_edges(graph) -> set[tuple[str, str]]:
    return {
        (edge.source, edge.target)
        for edge in graph.edges
        if edge.relationship == RelationshipType.DEPENDS_ON
        and graph.nodes[edge.source].entity_type == EntityType.PACKAGE
        and graph.nodes[edge.target].entity_type == EntityType.PACKAGE
    }


def test_spec_allows_package_to_package_dependency_in_the_reach_walk() -> None:
    spec = relationship_spec(RelationshipType.DEPENDS_ON)
    assert spec is not None
    assert spec.allows(EntityType.PACKAGE, EntityType.PACKAGE)
    assert spec.traversal_class is TraversalClass.DEPENDENCY
    assert RelationshipType.DEPENDS_ON in REACH_RELATIONSHIP_TYPES


def test_recorded_parent_becomes_one_parent_child_edge_with_depth_on_the_node() -> None:
    graph = build_unified_graph_from_report(
        _report(
            [
                _pkg("express", "4.17.1", direct=True),
                _pkg("body-parser", "1.19.0", direct=False, parent="express", depth=1),
                _pkg("qs", "6.7.0", direct=False, parent="body-parser", depth=2),
            ]
        )
    )

    assert _pkg_edges(graph) == {
        ("pkg:npm:express@4.17.1", "pkg:npm:body-parser@1.19.0"),
        ("pkg:npm:body-parser@1.19.0", "pkg:npm:qs@6.7.0"),
    }
    qs = graph.nodes["pkg:npm:qs@6.7.0"].attributes
    assert qs["is_direct"] is False and qs["dependency_depth"] == 2 and qs["parent_package"] == "body-parser"
    assert graph.nodes["pkg:npm:express@4.17.1"].attributes["is_direct"] is True


def test_ambiguous_or_missing_parent_draws_no_edge() -> None:
    graph = build_unified_graph_from_report(
        _report(
            [
                _pkg("lodash", "4.17.20", direct=True),
                _pkg("lodash", "4.17.21", direct=True),
                _pkg("orphan", "1.0.0", direct=False, parent="lodash", depth=1),
                _pkg("lost", "1.0.0", direct=False, parent="not-installed", depth=1),
            ]
        )
    )

    assert _pkg_edges(graph) == set()


def test_no_transitive_closure_is_materialized() -> None:
    chain = [_pkg("p0", "1.0.0", direct=True)] + [_pkg(f"p{i}", "1.0.0", direct=False, parent=f"p{i - 1}", depth=i) for i in range(1, 30)]
    graph = build_unified_graph_from_report(_report(chain))

    assert len(_pkg_edges(graph)) == 29
