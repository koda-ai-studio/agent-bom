"""Every report finding row reaches the graph as a finding node on its asset.

Dedicated projections (IaC, benchmarks, secrets, MCP audit, credential reach,
skill audit, CVE blast radius) run first and own their node shapes. This pass
runs last: a row whose node already exists only contributes its compliance
tags and, when the node is still unattached, its asset edge; any other row gets
a node keyed by :func:`finding_row_node_id`.

The node id is a pure function of the row, so a serialized report can carry
``finding_node_id`` without the graph that was built mid-scan, and a rebuild
from that report lands on the same node.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
from agent_bom.core.asset_types import entity_type_for_asset_type
from agent_bom.evidence.finding_node_ids import _dict, _text, finding_row_node_id, stamp_finding_node_ids
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.resource_aliases import _build_cloud_resource_alias_index, _resolve_cloud_resource_node_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_text

_FINDING_ENTITIES = frozenset({EntityType.VULNERABILITY, EntityType.MISCONFIGURATION})
_NO_INVENTED_ASSET = frozenset({"SECRET_SCAN"})
_OBSERVED_ASSETS = frozenset({EntityType.CLOUD_RESOURCE, EntityType.DATA_STORE, EntityType.CLUSTER})
# Asset kinds a scanner names that have no inventory alias of their own.
_ASSET_FALLBACK = {
    "model_file": EntityType.MODEL,
    "skill_file": EntityType.CONFIG_FILE,
    "container_image": EntityType.CONTAINER,
    "iam_role": EntityType.ROLE,
}
# Finding source -> (edge collector, evidence tier).
_COLLECTORS = {
    "MCP_SCAN": ("mcp-scan", "static_scan"),
    "CONTAINER": ("container-scan", "static_scan"),
    "SBOM": ("sbom-ingest", "static_scan"),
    "CLOUD_CIS": ("cloud-cis", "modeled_infrastructure"),
    "CLOUD_SECURITY": ("cloud-security", "modeled_infrastructure"),
    "PROXY": ("runtime-proxy", "runtime_observed"),
    "SAST": ("sast", "static_scan"),
    "SKILL": ("skill-audit", "static_scan"),
    "BROWSER_EXT": ("browser-extension-scan", "static_scan"),
    "EXTERNAL": ("external-import", "recorded"),
    "FILESYSTEM": ("filesystem-scan", "static_scan"),
    "PROMPT_SCAN": ("prompt-scan", "static_scan"),
    "SECRET_SCAN": ("secret-scan", "static_scan"),
    "DSPM": ("dspm", "recorded"),
    "MODEL_SCAN": ("model-scan", "static_scan"),
}


def row_compliance_tags(row: dict[str, Any]) -> set[str]:
    return {str(tag) for field in COMPLIANCE_TAG_FIELDS for tag in row.get(field) or [] if str(tag)}


class _AssetIndex:
    """Existing non-finding nodes addressable by a finding's asset fields."""

    def __init__(self, graph: UnifiedGraph) -> None:
        self.graph = graph
        self.by_identity: dict[str, set[str]] = defaultdict(set)
        self.by_label: dict[tuple[EntityType, str], set[str]] = defaultdict(set)
        for node in graph.nodes.values():
            if node.entity_type in _FINDING_ENTITIES:
                continue
            for key in ("canonical_id", "stable_id"):
                value = node.attributes.get(key)
                if isinstance(value, str) and value:
                    self.by_identity[value].add(node.id)
            self.by_label[(node.entity_type, node.label)].add(node.id)
        self.aliases = _build_cloud_resource_alias_index(graph)

    def _usable(self, node_id: Any) -> bool:
        node = self.graph.nodes.get(node_id) if isinstance(node_id, str) else None
        return node is not None and node.entity_type not in _FINDING_ENTITIES

    def resolve(self, row: dict[str, Any], entity: EntityType | None) -> str | None:
        asset, evidence = _dict(row.get("asset")), _dict(row.get("evidence"))
        identifier = _text(asset.get("identifier"))
        for candidate in (row.get("node_id"), identifier, evidence.get("resource_id"), evidence.get("identity_id")):
            if self._usable(candidate):
                return str(candidate)
        if entity == EntityType.CLOUD_RESOURCE and identifier:
            provider = _text(asset.get("provider")) or _text(row.get("provider")) or _text(asset.get("location"))
            resolved = _resolve_cloud_resource_node_id(self.graph, provider, identifier, alias_index=self.aliases)
            if self._usable(resolved):
                return resolved
        for key in (asset.get("canonical_id"), asset.get("stable_id")):
            matches = self.by_identity.get(key) if isinstance(key, str) else None
            if matches and len(matches) == 1:
                return next(iter(matches))
        name = _text(asset.get("name"))
        if entity is not None and name:
            matches = self.by_label.get((entity, name))
            if matches and len(matches) == 1:
                return next(iter(matches))
        return None


def _asset_entity(row: dict[str, Any]) -> EntityType | None:
    asset_type = _text(_dict(row.get("asset")).get("asset_type")).lower()
    return entity_type_for_asset_type(asset_type) or _ASSET_FALLBACK.get(asset_type)


def _ensure_asset_node(graph: UnifiedGraph, row: dict[str, Any], entity: EntityType, collector: str) -> str | None:
    """The asset a row names, added to the graph when no inventory node carries it."""
    asset = _dict(row.get("asset"))
    identifier = _text(asset.get("identifier")) or _text(asset.get("name"))
    canonical = _text(asset.get("canonical_id")) or _text(asset.get("stable_id"))
    if not identifier and not canonical:
        return None
    if entity == EntityType.CLOUD_RESOURCE and identifier:
        provider = _text(asset.get("provider")) or _text(asset.get("location")) or "generic"
        node_id = f"cloud_resource:{provider}:{identifier}"
    else:
        # Redacted path labels collide across directories; the canonical asset id does not.
        node_id = f"{entity.value}:{canonical or identifier}"
    identifier = identifier or canonical
    if node_id not in graph.nodes:
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=entity,
                label=sanitize_text(_text(asset.get("name")) or identifier, max_len=500),
                attributes={
                    "asset_type": _text(asset.get("asset_type")),
                    "identifier": sanitize_text(identifier, max_len=500),
                    **(_native_keys(row, asset, identifier) if entity == EntityType.CLOUD_RESOURCE else {}),
                },
                data_sources=[collector],
            )
        )
    return node_id


def _native_keys(row: dict[str, Any], asset: dict[str, Any], identifier: str) -> dict[str, str]:
    """Record the asset's native key so canonicalization can join it with other sources."""
    keys = {
        "cloud_provider": _text(asset.get("provider")).casefold(),
        "account_id": _text(row.get("account_ref") or asset.get("account_ref")),
    }
    if identifier.startswith(("arn:", "/subscriptions/", "projects/")):
        keys["resource_id"] = identifier
    elif "." in identifier and " " not in identifier and "/" not in identifier:
        keys["hostname"] = identifier
    return {key: value for key, value in keys.items() if value}


def _edge_for(finding: UnifiedNode, asset: UnifiedNode) -> tuple[str, str, RelationshipType] | None:
    vulnerable_to = relationship_spec(RelationshipType.VULNERABLE_TO)
    if vulnerable_to is not None and vulnerable_to.allows(asset.entity_type, finding.entity_type):
        return asset.id, finding.id, RelationshipType.VULNERABLE_TO
    affects = relationship_spec(RelationshipType.AFFECTS)
    if affects is not None and affects.allows(finding.entity_type, asset.entity_type):
        return finding.id, asset.id, RelationshipType.AFFECTS
    return None


def _has_asset_edge(graph: UnifiedGraph, node_id: str) -> bool:
    for edge in (*graph.edges_from(node_id), *graph.edges_to(node_id)):
        other = graph.nodes.get(edge.target if edge.source == node_id else edge.source)
        if other is not None and other.entity_type not in _FINDING_ENTITIES:
            return True
    return False


def _evidence(row: dict[str, Any], collector: str, tier: str) -> dict[str, Any]:
    if tier == "derived":
        return edge_evidence(collector, tier, "finding_row", derived_via="graph_analysis", finding_id=row.get("id"))
    return edge_evidence(collector, tier, "finding_row", finding_id=row.get("id"))


def _collector(row: dict[str, Any]) -> tuple[str, str]:
    if row.get("source") == "GRAPH_ANALYSIS":
        return "graph-analysis", "derived"
    return _COLLECTORS.get(_text(row.get("source")), ("finding-import", "static_scan"))


def _new_node(row: dict[str, Any], node_id: str, collector: str) -> UnifiedNode:
    evidence = _dict(row.get("evidence"))
    attributes: dict[str, Any] = {
        "finding_id": row.get("id"),
        "finding_type": row.get("finding_type"),
        "finding_source": row.get("source"),
    }
    for key in ("rule_id", "check_id", "category"):
        value = evidence.get(key)
        if isinstance(value, (str, int)) and value != "":
            attributes[key] = value
    vuln_id = _text(row.get("vulnerability_id")) or _text(row.get("cve_id"))
    if vuln_id:
        attributes["vulnerability_id"] = vuln_id
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.VULNERABILITY if node_id.startswith("vuln:") else EntityType.MISCONFIGURATION,
        label=sanitize_text(_text(row.get("title")) or _text(row.get("finding_type")) or "Finding", max_len=500),
        severity=_text(row.get("severity")).lower() or "unknown",
        attributes=attributes,
        compliance_tags=sorted(row_compliance_tags(row)),
        data_sources=[collector],
    )


def project_finding_rows(graph: UnifiedGraph, findings: Any) -> None:
    """Give every finding row a node with its compliance tags, attached to its asset."""
    if not isinstance(findings, list):
        return
    rows = [row for row in findings if isinstance(row, dict)]
    if not rows:
        return
    index = _AssetIndex(graph)
    for row in rows:
        node_id = finding_row_node_id(row)
        if node_id is None:
            continue
        collector, tier = _collector(row)
        node = graph.nodes.get(node_id)
        if node is None:
            node = _new_node(row, node_id, collector)
            graph.add_node(node)
        elif node.entity_type not in _FINDING_ENTITIES:
            continue
        else:
            tags = row_compliance_tags(row) - set(node.compliance_tags or [])
            if tags:
                node.compliance_tags = sorted({*(node.compliance_tags or []), *tags})
        if _has_asset_edge(graph, node_id):
            continue
        entity = _asset_entity(row)
        asset_id = index.resolve(row, entity)
        # Secret occurrences attach only to files the repository overlay recorded.
        if asset_id is None and entity is not None and row.get("source") not in _NO_INVENTED_ASSET:
            asset_id = _ensure_asset_node(graph, row, entity, collector)
        asset = graph.nodes.get(asset_id) if asset_id else None
        edge = _edge_for(node, asset) if asset is not None else None
        if edge is None:
            continue
        source, target, relationship = edge
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, evidence=_evidence(row, collector, tier)))
        if asset is not None and asset.entity_type in _OBSERVED_ASSETS and collector not in asset.data_sources:
            # A posture source that names a cloud asset is one more observation of it.
            asset.data_sources.append(collector)


__all__ = ["finding_row_node_id", "project_finding_rows", "row_compliance_tags", "stamp_finding_node_ids"]
