"""Scanned container images as ``container`` image nodes, not agents with MCP servers.

Image scans reuse the agent/server serialization as a package carrier: an
``image:<ref>`` agent holding one ``container-image`` (or ``oci-tarball``)
server. That shape is a transport, not topology, so the graph projects such a
carrier as one image node (``container_kind=image``) that contains its packages.
A Kubernetes workload that runs the same image depends on the same node.

A carrier is recognized only from recorded fields: the producer's
``metadata.inventory_role`` or an image ``source``, and every server's surface.
Real cloud workloads whose servers carry an image surface keep their agent.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.canonical_ids import mcp_server_graph_id_for
from agent_bom.core.image_ref import DIGEST_PREFIX, image_key, image_repository
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType

INVENTORY_ROLE = "container_image"
IMAGE_SOURCES = frozenset({"image", "image-tar", "kubernetes-image"})
_IMAGE_SURFACES = frozenset({"container-image", "oci-tarball"})


def image_node_id(ref: str, digest: str = "") -> str:
    """One image node per digest when known, else per the reference as written."""
    return f"container:image:{image_key(ref, digest)}"


def _metadata(agent: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = agent.get("metadata")
    return metadata if isinstance(metadata, Mapping) else {}


def is_image_carrier(agent: Mapping[str, Any]) -> bool:
    servers = [srv for srv in agent.get("mcp_servers") or [] if isinstance(srv, Mapping)]
    if not servers or any(str(srv.get("surface") or "") not in _IMAGE_SURFACES for srv in servers):
        return False
    return _metadata(agent).get("inventory_role") == INVENTORY_ROLE or str(agent.get("source") or "") in IMAGE_SOURCES


def carrier_image(agent: Mapping[str, Any]) -> tuple[str, str]:
    """``(reference, digest)`` the carrier recorded for its image."""
    metadata = _metadata(agent)
    servers = [srv for srv in agent.get("mcp_servers") or [] if isinstance(srv, Mapping)]
    ref = str(metadata.get("image_ref") or (servers[0].get("name") if servers else "") or "").strip()
    return ref, str(metadata.get("image_digest") or "")


def carrier_node_id(agent: Mapping[str, Any]) -> str | None:
    if not is_image_carrier(agent):
        return None
    ref, digest = carrier_image(agent)
    return image_node_id(ref, digest) if ref else None


def previous_carrier_ids(agent: Mapping[str, Any], agent_graph_id: str) -> list[str]:
    """The agent and server ids earlier builds gave this carrier, kept as aliases."""
    servers = [srv for srv in agent.get("mcp_servers") or [] if isinstance(srv, Mapping)]
    return sorted({agent_graph_id, *(mcp_server_graph_id_for(srv, dict(agent)) for srv in servers)})


def add_image_node(graph: UnifiedGraph, agent: Mapping[str, Any], node_id: str, data_source: str, aliases: list[str]) -> None:
    ref, _recorded = carrier_image(agent)
    digest = node_id.rsplit("@", 1)[1] if "@" in node_id.removeprefix("container:image:") else ""
    existing = graph.nodes.get(node_id)
    known = existing.attributes.get("identity", {}).get("aliases", []) if existing is not None else []
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.CONTAINER,
            label=f"image: {ref}",
            attributes={
                "container_kind": "image",
                "resource_type": "container_image",
                "image_ref": ref,
                "image_repository": image_repository(ref),
                "image_digest": digest if digest.startswith(DIGEST_PREFIX) else "",
                "image_source": str(agent.get("source") or ""),
                "identity": {"basis": "image_reference", "aliases": sorted({*known, *(a for a in aliases if a != node_id)})},
            },
            data_sources=[data_source or "image"],
            dimensions=NodeDimensions(surface="container-image"),
        )
    )
