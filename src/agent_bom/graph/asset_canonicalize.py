"""One graph node per real-world asset, whichever sources observed it.

Each source mints its own id for what it saw (inventory, audit trail, workload
protection, posture findings, runtime). :func:`canonicalize_assets` groups the
observations that share a strong identity key (see
:mod:`agent_bom.graph.asset_identity`) with a conflict-guarded union-find,
re-keys every group onto one deterministic id derived from its best key (never
from whichever source happened to run first) and keeps every observation's
provenance on the merged node. Weak-key matches never merge; they become one
reviewable ``POSSIBLY_CORRELATES_WITH`` candidate.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.asset_identity import (
    FAMILY_TYPES,
    IdentityKey,
    StrongKeyComponents,
    family_of,
    strong_key_components,
    strong_keys,
    weak_keys,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.node_aliases import drop_live_node_aliases
from agent_bom.graph.security_assertions import resolve_security_assertions
from agent_bom.graph.types import EntityType, RelationshipType

ANALYZER = "asset_canonicalization"
IDENTITY_SOURCE = "asset-canonicalization"
MAX_WEAK_BUCKET = 5
_NATIVE_ATTRIBUTES = ("arn", "resource_arn", "resource_id", "identifier", "kubernetes_uid", "image_digest", "principal_id")
_BOOKKEEPING = frozenset({"identity", "canonical_id", "source_ids", "stable_id", "risk_assessment"})
# A cluster outranks a generic resource record of the same native id.
_TYPE_PREFERENCE = (EntityType.CLUSTER, EntityType.DATA_STORE, EntityType.CONTAINER, EntityType.ROLE)


@dataclass(slots=True)
class _Observation:
    node_id: str
    family: str
    entity_type: EntityType
    label: str
    strong: list[IdentityKey]
    weak: list[IdentityKey]
    attributes: dict[str, Any]
    data_sources: list[str]
    richness: tuple[int, int, str] | None = None


def _observations(graph: UnifiedGraph) -> dict[str, _Observation]:
    observed: dict[str, _Observation] = {}
    for entity_type in sorted({entity for types in FAMILY_TYPES.values() for entity in types}, key=lambda item: item.value):
        for node in graph.iter_nodes_by_type(entity_type):
            family = family_of(node)
            if not family:
                continue
            strong, weak = strong_keys(node), weak_keys(node)
            if strong or weak:
                observed[node.id] = _Observation(
                    node.id, family, entity_type, node.label, strong, weak, dict(node.attributes), list(node.data_sources)
                )
    return observed


def _components(observed: dict[str, _Observation]) -> StrongKeyComponents:
    return strong_key_components({node_id: (item.family, item.strong) for node_id, item in observed.items()})


def _richness(item: _Observation) -> tuple[int, int, str]:
    if item.richness is None:
        filled = sum(1 for key, value in item.attributes.items() if key not in _BOOKKEEPING and value not in (None, "", [], {}))
        item.richness = (len(item.strong), filled, item.node_id)
    return item.richness


def _merged_entity_type(members: list[_Observation]) -> EntityType:
    types = {item.entity_type for item in members}
    return next((preferred for preferred in _TYPE_PREFERENCE if preferred in types), max(members, key=_richness).entity_type)


def _canonical_id(members: list[_Observation], entity_type: EntityType, identity: tuple[IdentityKey, bool]) -> tuple[str, IdentityKey]:
    # A key shared with a conflicting component cannot name this one, or the
    # rekey would collapse the two groups the union-find kept apart.
    best, unique = identity
    canonical = f"{entity_type.value}:{best.provider or 'native'}:{best.namespace}:{best.value}"
    return (canonical if unique else f"{canonical}#{min(item.node_id for item in members)}"), best


def _merge_attributes(members: list[_Observation]) -> tuple[dict[str, Any], list[str]]:
    ordered = sorted(members, key=_richness, reverse=True)
    merged = dict(ordered[0].attributes)
    conflicts: set[str] = {
        field
        for item in members
        if isinstance(item.attributes.get("identity"), dict)
        for field in item.attributes["identity"].get("conflict_fields", [])
        if isinstance(field, str)
    }
    for item in ordered[1:]:
        for key, value in item.attributes.items():
            if key in _BOOKKEEPING or value in (None, "", [], {}):
                continue
            if merged.get(key) in (None, "", [], {}):
                merged[key] = value
            elif merged[key] != value:
                conflicts.add(key)
    return merged, sorted(conflicts)


def _provenance(members: list[_Observation], canonical_id: str, best: IdentityKey, conflicts: list[str]) -> dict[str, Any]:
    aliases: set[str] = set()
    observations: dict[tuple[str, str], dict[str, str]] = {}
    for item in members:
        recorded = item.attributes.get("identity")
        prior: dict[str, Any] = recorded if isinstance(recorded, dict) else {}
        aliases.update(alias for alias in prior.get("aliases", []) if isinstance(alias, str))
        for record in prior.get("observations", []):
            if isinstance(record, dict):
                observations[(str(record.get("node_id")), str(record.get("data_source")))] = record
        if item.node_id != canonical_id:
            aliases.add(item.node_id)
        key = item.strong[0] if item.strong else best
        native = next((str(item.attributes[name]) for name in _NATIVE_ATTRIBUTES if item.attributes.get(name)), key.value)
        for source in item.data_sources or ["unknown"]:
            record = {"data_source": source, "native_id": native, "key_basis": key.namespace, "node_id": item.node_id}
            observations[(item.node_id, source)] = record
    return {
        "canonical_key": best.text,
        "basis": best.namespace,
        "aliases": sorted(aliases - {canonical_id}),
        "observations": [observations[key] for key in sorted(observations)],
        "conflict_fields": conflicts,
    }


@dataclass(slots=True)
class _Group:
    canonical_id: str
    entity_type: EntityType
    label: str
    attributes: dict[str, Any]
    data_sources: list[str]


def _groups(observed: dict[str, _Observation], components: StrongKeyComponents, scan_id: str) -> tuple[dict[str, str], list[_Group]]:
    members_by_root: dict[str, list[_Observation]] = {}
    for node_id in sorted(observed):
        if observed[node_id].strong:
            members_by_root.setdefault(components.find(node_id), []).append(observed[node_id])
    mapping: dict[str, str] = {}
    groups: list[_Group] = []
    identities = components.identities()
    for root, members in members_by_root.items():
        if len(members) < 2:
            continue
        entity_type = _merged_entity_type(members)
        canonical_id, best = _canonical_id(members, entity_type, identities[root])
        attributes, conflicts = _merge_attributes(members)
        assertions = resolve_security_assertions(
            ((source, scan_id, item.node_id, item.attributes) for item in members for source in item.data_sources or ["unknown"]),
            attributes,
        )
        attributes["identity"] = _provenance(members, canonical_id, best, sorted(set(conflicts) | assertions.keys()))
        if assertions:
            attributes["identity"]["conflicts"] = assertions
        attributes["canonical_id"] = canonical_graph_node_id(entity_type.value, canonical_id)
        sources = list(dict.fromkeys(source for item in sorted(members, key=_richness, reverse=True) for source in item.data_sources))
        label = max(members, key=_richness).label
        groups.append(_Group(canonical_id, entity_type, label, attributes, sources))
        mapping.update({item.node_id: canonical_id for item in members if item.node_id != canonical_id})
    return mapping, groups


def _candidate_edges(observed: dict[str, _Observation], mapping: dict[str, str], components: StrongKeyComponents) -> list[UnifiedEdge]:
    buckets: dict[tuple[str, str, str], set[str]] = {}
    for item in observed.values():
        for key in item.weak:
            buckets.setdefault((item.family, key.namespace, key.value), set()).add(mapping.get(item.node_id, item.node_id))
    strong_by_id: dict[str, dict[str, str]] = {}
    sources_by_id: dict[str, set[str]] = {}
    for item in observed.values():
        canonical = mapping.get(item.node_id, item.node_id)
        strong_by_id.setdefault(canonical, {}).update(components.keys.get(components.find(item.node_id), {}) if item.strong else {})
        sources_by_id.setdefault(canonical, set()).update(item.data_sources)
    signals: dict[tuple[str, str], set[str]] = {}
    for (_family, namespace, _value), ids in sorted(buckets.items()):
        if not 2 <= len(ids) <= MAX_WEAK_BUCKET:
            continue
        for left, right in combinations(sorted(ids), 2):
            if set(strong_by_id.get(left, {})) & set(strong_by_id.get(right, {})):
                continue  # both carry a native id of one kind and they differ: provably two assets
            signals.setdefault((left, right), set()).add(namespace)
    return [
        UnifiedEdge(
            source=left,
            target=right,
            relationship=RelationshipType.POSSIBLY_CORRELATES_WITH,
            direction="bidirectional",
            traversable=False,
            evidence=edge_evidence(
                IDENTITY_SOURCE,
                "derived",
                "weak_identity_match",
                derived_via="identity_keys",
                matched_signals=sorted(found),
                confidence="medium" if len(found) > 1 else "low",
                sources=sorted(sources_by_id.get(left, set()) | sources_by_id.get(right, set())),
            ),
        )
        for (left, right), found in sorted(signals.items())
    ]


def _apply_groups(graph: UnifiedGraph, groups: Iterable[_Group]) -> None:
    for group in groups:
        node: UnifiedNode | None = graph.get_node(group.canonical_id)
        if node is None:
            continue
        node.entity_type = group.entity_type
        node.label = group.label
        node.attributes = group.attributes
        node.data_sources = group.data_sources


def canonicalize_assets(graph: UnifiedGraph) -> dict[str, str]:
    """Merge every strong-key group onto one node; returns ``alias id -> canonical id``."""
    observed = _observations(graph)
    components = _components(observed)
    mapping, groups = _groups(observed, components, graph.scan_id)
    dropped = graph.rekey_nodes(mapping) if mapping else 0
    _apply_groups(graph, groups)
    candidates = _candidate_edges(observed, mapping, components)
    for edge in candidates:
        graph.add_edge(edge)
    drop_live_node_aliases(graph)
    # A later pass (assets a finding row named after analysis) adds to the first.
    prior = graph.analysis_status.get(ANALYZER)
    if prior is None and not observed:
        return mapping  # nothing in the graph carries an asset identity key
    before = prior.observed if prior is not None else {}
    # Count each current asset's disagreements once, including earlier passes.
    grouped_ids = set(mapping) | {group.canonical_id for group in groups}
    identities = [group.attributes["identity"] for group in groups] + [
        item.attributes["identity"]
        for node_id, item in observed.items()
        if node_id not in grouped_ids and isinstance(item.attributes.get("identity"), dict)
    ]
    attribute_conflicts = sum(len(identity.get("conflict_fields", [])) for identity in identities)
    security_conflicts = sum(len(identity.get("conflicts", {})) for identity in identities)
    strong_conflicts = components.conflicts + int(before.get("strong_key_conflicts", 0))
    conflicts = strong_conflicts + attribute_conflicts
    reasons = []
    if strong_conflicts:
        reasons.append("conflicting_strong_keys")
    if attribute_conflicts:
        reasons.append("conflicting_attributes")
    if security_conflicts:
        reasons.append("conflicting_security_assertions")
    graph.analysis_status[ANALYZER] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if conflicts else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(reasons),
        observed={
            "observations": max(len(observed), int(before.get("observations", 0))),
            "merged_groups": len(groups) + int(before.get("merged_groups", 0)),
            "aliases": len(mapping) + int(before.get("aliases", 0)),
            "candidate_edges": len(candidates),
            "conflicts": conflicts,
            "strong_key_conflicts": strong_conflicts,
            "security_assertion_conflicts": security_conflicts,
            "self_edges_dropped": dropped + int(before.get("self_edges_dropped", 0)),
        },
    )
    return mapping
