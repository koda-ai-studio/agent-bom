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
from agent_bom.core.reachability import node_reachability
from agent_bom.evidence.finding_node_ids import _dict, _text, finding_row_node_id, stamp_finding_node_ids
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.container_kind import container_kind_attributes
from agent_bom.graph.declared_assets import declared_asset
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import SOURCE_TIERS, edge_evidence
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
# Finding source -> edge collector; the collector's tier comes from SOURCE_TIERS.
_COLLECTORS = {
    "IAC_SCAN": "iac",
    "MCP_SCAN": "mcp-scan",
    "CONTAINER": "container-scan",
    "SBOM": "sbom-ingest",
    "CLOUD_CIS": "cloud-cis",
    "CLOUD_SECURITY": "cloud-security",
    "PROXY": "runtime-proxy",
    "SAST": "sast",
    "SKILL": "skill-audit",
    "BROWSER_EXT": "browser-extension-scan",
    "EXTERNAL": "external-import",
    "FILESYSTEM": "filesystem-scan",
    "PROMPT_SCAN": "prompt-scan",
    "SECRET_SCAN": "secret-scan",
    "DSPM": "dspm",
    "MODEL_SCAN": "model-scan",
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
        # Producers record a node's id without its type prefix (an MCP server's graph uuid).
        prefixed = f"{entity.value}:{identifier}" if entity is not None and identifier else None
        for candidate in (row.get("node_id"), identifier, prefixed, evidence.get("resource_id"), evidence.get("identity_id")):
            if self._usable(candidate):
                return str(candidate)
        if entity == EntityType.CLOUD_RESOURCE and identifier:
            provider = _text(asset.get("provider")) or _text(row.get("provider")) or _text(asset.get("location"))
            account = _text(row.get("account_ref") or asset.get("account_ref"))
            resolved = _resolve_cloud_resource_node_id(self.graph, provider, identifier, alias_index=self.aliases, account_id=account)
            if self._usable(resolved):
                return resolved
        # The asset identifier is often the inventory entity's canonical id, not its graph id
        # (a config-scoped agent is ``agent:cfg-…:<name>``, its identifier the agent's stable id).
        for key in (identifier, asset.get("canonical_id"), asset.get("stable_id")):
            matches = self.by_identity.get(key) if isinstance(key, str) else None
            if matches and len(matches) == 1:
                return next(iter(matches))
        return None

    def label_candidates(self, row: dict[str, Any], entity: EntityType | None, asset_id: str) -> list[str]:
        """Same-label nodes a name-only row may describe; a display name proposes, never binds."""
        asset = _dict(row.get("asset"))
        name = _text(asset.get("name"))
        qualified = any(_text(asset.get(key)) for key in ("identifier", "canonical_id", "stable_id"))
        if entity is None or not name or qualified:
            return []
        return sorted(node_id for node_id in self.by_label.get((entity, name), ()) if node_id != asset_id)


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
    declared = declared_asset(row)
    if declared is not None:
        node_id, entity = declared.node_id, declared.entity_type
    elif entity == EntityType.CLOUD_RESOURCE and identifier:
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
                    **(_native_keys(row, asset, identifier) if declared is not None or entity == EntityType.CLOUD_RESOURCE else {}),
                    **(container_kind_attributes(asset) if entity == EntityType.CONTAINER else {}),
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
    collector = _COLLECTORS.get(_text(row.get("source")))
    return (collector, SOURCE_TIERS[collector]) if collector else ("finding-import", "static_scan")


def vulnerability_signal_attributes(row: dict[str, Any]) -> dict[str, Any]:
    """Exploit signals a vulnerability finding carries onto its graph node.

    Attack-path ranking and toxic-combination rules read ``is_kev`` and EPSS from
    the node, so dropping them here demotes exploited-in-the-wild paths.
    """
    evidence = _dict(row.get("evidence"))
    attributes: dict[str, Any] = {"is_kev": bool(row.get("is_kev") or evidence.get("is_kev"))}
    vuln_id = _text(row.get("vulnerability_id")) or _text(row.get("cve_id"))
    if vuln_id:
        attributes["vulnerability_id"] = vuln_id
    for key in ("epss_score", "cvss_score"):
        value = row.get(key, evidence.get(key))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            attributes[key] = value
    fixed = _text(row.get("fixed_version"))
    if fixed:
        attributes["fixed_version"] = fixed
    return attributes


def _occurrence_verdict_attributes(row: dict[str, Any]) -> dict[str, Any]:
    """The row's own reachability verdict and effective reach for its vulnerability node."""
    reach = node_reachability(row)
    attributes: dict[str, Any] = {"reachability": reach.verdict.value, "reachability_basis": list(reach.basis)}
    score = row.get("effective_reach_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        attributes["effective_reach_score"] = score
    band = _text(row.get("effective_reach_band"))
    if band:
        attributes["effective_reach_band"] = band
    return attributes


def finding_signal_attributes(finding: Any) -> dict[str, Any]:
    """:func:`vulnerability_signal_attributes` for a ``Finding`` object."""
    return vulnerability_signal_attributes(
        {key: getattr(finding, key, None) for key in ("vulnerability_id", "is_kev", "epss_score", "cvss_score", "fixed_version")}
    )


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
    is_vulnerability = node_id.startswith("vuln:")
    if is_vulnerability:
        attributes.update(vulnerability_signal_attributes(row))
        attributes.update(_occurrence_verdict_attributes(row))
    else:
        vuln_id = _text(row.get("vulnerability_id")) or _text(row.get("cve_id"))
        if vuln_id:
            attributes["vulnerability_id"] = vuln_id
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.VULNERABILITY if is_vulnerability else EntityType.MISCONFIGURATION,
        label=sanitize_text(_text(row.get("title")) or _text(row.get("finding_type")) or "Finding", max_len=500),
        severity=_text(row.get("severity")).lower() or "unknown",
        attributes=attributes,
        compliance_tags=sorted(row_compliance_tags(row)),
        data_sources=[collector],
    )


def _propose_label_matches(graph: UnifiedGraph, asset: UnifiedNode, candidates: list[str], collector: str) -> None:
    spec = relationship_spec(RelationshipType.POSSIBLY_CORRELATES_WITH)
    for candidate_id in candidates:
        candidate = graph.nodes.get(candidate_id)
        if candidate is None or spec is None or not spec.allows(asset.entity_type, candidate.entity_type):
            continue
        graph.add_edge(
            UnifiedEdge(
                source=asset.id,
                target=candidate_id,
                relationship=RelationshipType.POSSIBLY_CORRELATES_WITH,
                evidence=edge_evidence(collector, "derived", "finding_row", derived_via="label_match"),
            )
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
        # A connector projection that already materialized the row owns its node.
        declared = graph.nodes.get(_text(row.get("finding_node_id")))
        node_id = declared.id if declared is not None and declared.entity_type in _FINDING_ENTITIES else finding_row_node_id(row)
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
        if asset is None or edge is None:
            continue
        source, target, relationship = edge
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, evidence=_evidence(row, collector, tier)))
        _propose_label_matches(graph, asset, index.label_candidates(row, entity, asset.id), collector)
        if asset.entity_type in _OBSERVED_ASSETS and collector not in asset.data_sources:
            # A posture source that names a cloud asset is one more observation of it.
            asset.data_sources.append(collector)


__all__ = [
    "finding_row_node_id",
    "finding_signal_attributes",
    "project_finding_rows",
    "row_compliance_tags",
    "stamp_finding_node_ids",
    "vulnerability_signal_attributes",
]
