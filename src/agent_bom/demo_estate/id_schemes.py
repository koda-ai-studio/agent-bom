"""Demo node ids in the graph builder's canonical spelling, plus the ids they retired.

The live builder names a package ``pkg:<ecosystem>:<name>@<version>``, an
organization ``org:<provider>:<id>`` and a configuration finding
``misconfig:<source>:<id>``. The demo used to mint ``package:``,
``organization:`` and ``mc:`` spellings for the same kinds. Each retired id is
recorded as a node alias so saved links, stored snapshots and older findings
still resolve.
"""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node_aliases import record_node_aliases
from agent_bom.package_utils import canonical_package_key

_RETIRED_ORG_PREFIX = "organization:"
_IMAGE_QUALIFIER = ":image:"


def estate_package_asset_id(ecosystem: str, name: str, version: str, image_digest: str) -> str:
    """One package occurrence inside one image: the canonical package id, qualified by image digest.

    The occurrence is the estate's unit of evidence (each image's package row
    carries its own finding), so the image digest stays in the id.
    """
    return f"pkg:{canonical_package_key(name, version, ecosystem)}{_IMAGE_QUALIFIER}{image_digest[:12]}"


def retired_package_asset_id(ecosystem: str, name: str, version: str, image_digest: str) -> str:
    return f"package:{ecosystem.lower()}:{name}@{version}:{image_digest[:12]}"


def retired_estate_asset_ids(asset_id: str, resource_type: str, native_id: str, tags: dict[str, str]) -> list[str]:
    """Ids this asset was published under before the canonical spelling."""
    if resource_type == "organization" and asset_id.startswith("org:"):
        return [f"{_RETIRED_ORG_PREFIX}{native_id}"]
    if resource_type == "package" and _IMAGE_QUALIFIER in asset_id:
        ecosystem, name, version = tags.get("ecosystem", ""), tags.get("package_name", ""), tags.get("package_version", "")
        digest = asset_id.rsplit(_IMAGE_QUALIFIER, 1)[1]
        if ecosystem and name and version:
            return [retired_package_asset_id(ecosystem, name, version, digest)]
    return []


def showcase_misconfig_id(slug: str) -> str:
    return f"misconfig:showcase:{slug}"


_SHOWCASE_MISCONFIG_SLUGS = ("pii-private", "pii-public", "sg-open")


def record_retired_showcase_ids(graph: UnifiedGraph) -> None:
    """Keep the showcase's former ``mc:<slug>`` finding ids resolvable."""
    for slug in _SHOWCASE_MISCONFIG_SLUGS:
        node = graph.nodes.get(showcase_misconfig_id(slug))
        if node is not None:
            record_node_aliases(node, [f"mc:{slug}"])
