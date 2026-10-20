"""Estate images carry multi-level recorded dependency trees, and the graph walks them.

Every estate package chain used to be exactly one deep (the first package of an
ecosystem "parented" the rest), so no vulnerable package ever sat below a clean
one and transitive impact was never exercised. Each image now records a
first-party service package that pulls in a first-party SDK and the third-party
packages, with the third-party packages nested under their real upstream parent
(``requests`` -> ``certifi``, ``flask`` -> ``werkzeug``/``jinja2``,
``langchain`` -> ``requests``) when both are in the image.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.fixture(scope="module")
def estate():
    return build_demo_estate(tenant_id="default")


@pytest.fixture(scope="module")
def findings(estate):
    return build_estate_findings(estate)


@pytest.fixture(scope="module")
def graph(estate, findings):
    built = UnifiedGraph(scan_id="estate-depth", tenant_id="default")
    project_estate_into_graph(built, estate, findings=findings)
    return built


def _packages(estate):
    return [a for a in estate.assets if a.resource_type == "package"]


def test_trees_are_several_levels_deep(estate) -> None:
    depths = Counter(int(a.tags["dependency_depth"]) for a in _packages(estate))
    assert set(depths) >= {0, 1, 2, 3}, depths
    assert depths[0] < depths[1] + depths[2] + depths[3]


def test_recorded_parents_resolve_inside_the_same_image(estate, graph) -> None:
    by_image: dict[str, dict[str, object]] = {}
    for asset in _packages(estate):
        by_image.setdefault(asset.tags["container_image"], {})[asset.tags["package_name"]] = asset
    edges = {(e.source, e.target) for e in graph.edges if e.relationship is RelationshipType.DEPENDS_ON}
    for image, packages in by_image.items():
        for asset in packages.values():
            parent_name = asset.tags.get("parent_package")
            if asset.tags["is_direct"] == "true":
                assert not parent_name and asset.tags["dependency_depth"] == "0"
                assert (image, asset.asset_id) in edges
                continue
            parent = packages[parent_name]
            assert int(asset.tags["dependency_depth"]) == int(parent.tags["dependency_depth"]) + 1
            assert (parent.asset_id, asset.asset_id) in edges


def test_a_clean_parent_sits_above_a_vulnerable_child(estate, findings) -> None:
    vulnerable = {f.asset.identifier for f in findings if f.finding_type.value == "CVE"}
    by_name = {(a.tags["container_image"], a.tags["package_name"]): a for a in _packages(estate)}
    clean_over_vulnerable = [
        asset
        for asset in _packages(estate)
        if asset.asset_id in vulnerable
        and asset.tags.get("parent_package")
        and by_name[(asset.tags["container_image"], asset.tags["parent_package"])].asset_id not in vulnerable
    ]
    assert clean_over_vulnerable
    first_party = [a for a in _packages(estate) if a.tags.get("first_party") == "true"]
    assert first_party and not vulnerable & {a.asset_id for a in first_party}


def test_third_party_nesting_follows_real_upstream_parents(estate) -> None:
    upstream = {"certifi": "requests", "werkzeug": "flask", "jinja2": "flask", "requests": "langchain"}
    by_image: dict[str, set[str]] = {}
    for asset in _packages(estate):
        by_image.setdefault(asset.tags["container_image"], set()).add(asset.tags["package_name"])
    nested = 0
    for asset in _packages(estate):
        name, parent = asset.tags["package_name"], asset.tags.get("parent_package")
        if name in upstream and upstream[name] in by_image[asset.tags["container_image"]]:
            assert parent == upstream[name]
            nested += 1
    assert nested > 0


def test_impact_walks_up_through_every_level(estate, findings, graph) -> None:
    deepest = max(
        (f for f in findings if f.finding_type.value == "CVE"),
        key=lambda f: int(graph.nodes[f.asset.identifier].attributes["dependency_depth"]),
    )
    package = graph.nodes[deepest.asset.identifier]
    assert int(package.attributes["dependency_depth"]) >= 3
    image = package.attributes["tags"]["container_image"]
    affected = set(graph.impact_of(deepest.finding_node_id, max_depth=12)["affected_nodes"])
    assert package.id in affected and image in affected
    ancestors = set(graph.impact_of(package.id, max_depth=12)["affected_nodes"])
    # The image lists every package it ships; the recorded parent is the one other holder.
    holders = {e.source for e in graph.edges if e.target == package.id and e.relationship is RelationshipType.DEPENDS_ON}
    parents = {p for p in holders if graph.nodes[p].entity_type is EntityType.PACKAGE}
    assert holders == parents | {image} and len(parents) == 1
    assert parents <= ancestors and image in ancestors
