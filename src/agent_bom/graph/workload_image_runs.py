"""Workload --runs--> image when the workload pins the image's exact digest.

An image (registry image, SBOM subject) and the workload running it (pod,
deployment, task) stay two nodes: identity keys never merge across those
families (:mod:`agent_bom.graph.asset_identity`). When a deployment and an
image scan arrive from different sources, this adds the one edge that joins
them, so the workload reaches the image's packages and findings through it.

Packages hang under the image. A workload reaches them only via ``runs``, and
component-path derivation treats ``runs`` as a holding hop, so the image is no
longer a separate path entry once a workload runs it.

Only a ``sha256`` digest links; a tag names a moving target and never does.
The subtype is the recorded ``container_kind`` / ``resource_type``; without
one, the collector the node came from decides (an SBOM or image scan
describes an image, a Kubernetes or IaC read describes a workload). A node no
rule classifies is never linked.
"""

from __future__ import annotations

import re

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.container_kind import IMAGE, WORKLOAD, container_kind
from agent_bom.graph.correlation_scope import CORRELATION_IDENTITY_VERSION
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

SOURCE = "image-digest-correlation"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST_KEYS = ("image_digest", "digest", "repo_digest")
_IMAGE_SOURCES = frozenset({"cyclonedx_sbom", "spdx_sbom", "sbom", "image", "image_scan", "container_image_scan"})
_WORKLOAD_SOURCES = frozenset({"kubernetes", "kubernetes_iac", "kubernetes_inventory", "kubernetes_manifest", "ecs", "ecs_task"})


def _kind(node: UnifiedNode) -> str:
    recorded = container_kind(node.attributes)
    if recorded:
        return recorded
    sources = {str(source).casefold() for source in node.data_sources}
    image, workload = bool(sources & _IMAGE_SOURCES), bool(sources & _WORKLOAD_SOURCES)
    if image != workload:
        return IMAGE if image else WORKLOAD
    return ""


def _digests(node: UnifiedNode) -> set[str]:
    found: set[str] = set()
    for key in _DIGEST_KEYS:
        value = node.attributes.get(key)
        if isinstance(value, str):
            found.update(match.group(0) for match in [_DIGEST.search(value.casefold())] if match)
    return found


def link_workload_images(graph: UnifiedGraph) -> int:
    """Add one ``runs`` edge per (workload, image) pair sharing a digest; returns how many were added."""
    images: dict[str, list[UnifiedNode]] = {}
    workloads: list[tuple[UnifiedNode, set[str]]] = []
    for node in graph.iter_nodes_of_types((EntityType.CONTAINER,)):
        digests = _digests(node)
        if not digests:
            continue
        kind = _kind(node)
        if kind == IMAGE:
            for digest in digests:
                images.setdefault(digest, []).append(node)
        elif kind == WORKLOAD:
            workloads.append((node, digests))
    if not images:
        return 0
    existing = {(edge.source, edge.target) for edge in graph.edges}
    added = 0
    for workload, digests in sorted(workloads, key=lambda item: item[0].id):
        for digest in sorted(digests):
            for image in sorted(images.get(digest, []), key=lambda node: node.id):
                if image.id == workload.id or (workload.id, image.id) in existing:
                    continue
                graph.add_edge(_runs_edge(workload, image, digest))
                existing.add((workload.id, image.id))
                added += 1
    return added


def _runs_edge(workload: UnifiedNode, image: UnifiedNode, digest: str) -> UnifiedEdge:
    return UnifiedEdge(
        source=workload.id,
        target=image.id,
        relationship=RelationshipType.RUNS,
        evidence=edge_evidence(
            SOURCE,
            "derived",
            "image_digest_match",
            derived_via=["image_digest"],
            image_digest=digest,
            workload_node_id=workload.id,
            image_node_id=image.id,
            workload_sources=sorted(workload.data_sources),
            image_sources=sorted(image.data_sources),
        ),
        provenance=_provenance(workload, image),
    )


def _scan_ids(node: UnifiedNode) -> list[str]:
    correlation = node.attributes.get("correlation")
    raw = correlation.get("source_scan_ids") if isinstance(correlation, dict) else None
    return [str(item) for item in raw if str(item).strip()] if isinstance(raw, list) else []


def _provenance(workload: UnifiedNode, image: UnifiedNode) -> dict[str, object]:
    """On a correlated graph, the scans that observed either endpoint, under the current identity version."""
    scans = sorted({*_scan_ids(workload), *_scan_ids(image)})
    if not scans:
        return {"source": SOURCE}
    return {"source": SOURCE, "correlation": {"identity_version": CORRELATION_IDENTITY_VERSION, "source_scan_ids": scans}}


__all__ = ["SOURCE", "link_workload_images"]
