"""The estate's recorded image package tree, projected the way a live scan's is.

Each image's inventory records which packages it declares directly and which
were pulled in by another package of the same ecosystem
(:mod:`agent_bom.demo_estate.estate_package_tree`). Those recorded
fields become ``is_direct``/``dependency_depth``/``parent_package`` on the
package node and one ``DEPENDS_ON`` edge per parent/child pair, resolved by the
same rule the live builder uses (:mod:`agent_bom.core.package_lineage`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from agent_bom.demo_estate.enterprise import EstateAsset
from agent_bom.demo_estate.estate_edges import ESTATE_DATA_SOURCE
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.package_dependency_projection import project_package_dependencies


def _record(asset: EstateAsset) -> dict[str, Any]:
    tags = asset.tags
    return {
        "stable_id": asset.asset_id,
        "name": tags.get("package_name", ""),
        "ecosystem": tags.get("ecosystem", ""),
        "is_direct": tags.get("is_direct") != "false",
        "parent_package": tags.get("parent_package") or None,
    }


def project_estate_package_lineage(graph: UnifiedGraph, assets: Sequence[EstateAsset]) -> int:
    """Stamp recorded depth/directness on package nodes and draw parent -> child edges."""
    by_image: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in assets:
        node = graph.nodes.get(asset.asset_id)
        if asset.resource_type != "package" or node is None or "dependency_depth" not in asset.tags:
            continue
        record = _record(asset)
        node.attributes.update(
            is_direct=record["is_direct"],
            dependency_depth=int(asset.tags["dependency_depth"]),
            parent_package=record["parent_package"] or "",
        )
        by_image[asset.tags.get("container_image", "")].append(record)
    return sum(
        project_package_dependencies(graph, records, node_id_for=lambda pkg: str(pkg["stable_id"]), data_source=ESTATE_DATA_SOURCE)
        for image, records in sorted(by_image.items())
        if image
    )
