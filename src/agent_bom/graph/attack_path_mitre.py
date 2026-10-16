"""Typed MITRE ATT&CK / ATLAS technique enrichment for attack paths (#4108).

Derives *potential* technique/tactic mappings for each hop of an
:class:`~agent_bom.graph.container.AttackPath` from source-backed prerequisites
in the hop's typed edge and evidence — never by parsing the human-readable ``summary`` / edge-label
text. A hop whose evidence maps to no known technique is left UNMAPPED
(fail-closed / honest): the kill-chain surfaces only the techniques the evidence
supports.

Every emitted ``technique_id`` and its ``tactics`` resolve against the bundled
catalogs (``mitre_fetch`` for ATT&CK, ``atlas_fetch`` for ATLAS) exactly like the
catalog-freshness tests validate — no dangling identifiers. Tactics are read from
the catalog, never hardcoded here.

Honesty: these are mapped/potential techniques for the kill-chain *sequence*, not
detections. Nothing in this module asserts observed attacker activity.
"""

from __future__ import annotations

from agent_bom.graph.compromise import _scope_gaps
from agent_bom.graph.consequence.eligibility import _receipt_scope
from agent_bom.graph.container import AttackPath, TechniqueMapping, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.hop_evidence import HopAuthorityEvidence, authority_evidence, runtime_evidence_references
from agent_bom.graph.path_evidence import _runtime_outcome, _runtime_state, resolve_typed_hop
from agent_bom.graph.types import EntityType, RelationshipType

# A catalog identifier is not evidence of its prerequisites. These narrow rules
# map recorded behavior/permissions to potential techniques, never detections.
_ATTACK = "attack"
_ATLAS = "atlas"
_VULN_RELS = frozenset({RelationshipType.VULNERABLE_TO, RelationshipType.EXPLOITABLE_VIA})
_STORAGE_READS = {
    ("gcp", "storage.objects.get"),
    ("azure", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"),
}


def relationship_evidence_basis(edge: UnifiedEdge) -> str | None:
    """Use explicit collector semantics; topology alone never implies observation."""
    for values in (edge.provenance, edge.evidence):
        for key in ("basis", "evidence_basis", "evidence_tier", "tier"):
            value = values.get(key)
            if value in ("observed", "runtime_observed", "inferred", "modeled"):
                return str(value)
            if value == "modeled_infrastructure":
                return "modeled"
        if values.get("source") == "modeled_policy":
            return "modeled"
    return None


def _storage_read_receipt(graph: UnifiedGraph, edge: UnifiedEdge) -> bool:
    """Exact native authorization scope; no generic database/storage inference.

    T1530: https://attack.mitre.org/techniques/T1530/ (object-storage data).
    A recorded allow supplies a modeled prerequisite, not collection/exfiltration.
    """

    raw = authority_evidence(edge.evidence)
    if raw is None or raw["status"] != "recorded":
        return False
    authority = HopAuthorityEvidence.model_validate(raw)
    scoped = _receipt_scope(graph, edge)
    source, target = scoped.nodes.get(edge.source), scoped.nodes.get(edge.target)
    if source is None or target is None or source.attributes.get("authorization_boundaries_truncated"):
        return False
    # Conflicting/negative receipts stay unresolved; never select the allow.
    if any(record.decision != "allow" for record in authority.decisions):
        return False
    boundaries = source.attributes.get("authorization_boundaries", [])
    if isinstance(boundaries, list) and any(isinstance(row, dict) and row.get("target_node_id") == edge.target for row in boundaries):
        return False
    return any(
        (record.provider, record.action) in _STORAGE_READS
        and bool(record.binding_ids and record.observed_at)
        and not _scope_gaps(record, source, target)
        for record in authority.decisions
    )


def _candidate(graph: UnifiedGraph, edge: UnifiedEdge) -> tuple[str, str, str, str] | None:
    """Return (technique, catalog, basis, explanation) for supported prerequisites."""

    source, target = graph.nodes.get(edge.source), graph.nodes.get(edge.target)
    if source is None or target is None or _runtime_outcome(edge) in {"blocked", "failed"}:
        return None
    if edge.relationship == RelationshipType.CAN_ACCESS and _storage_read_receipt(graph, edge):
        return (
            "T1530",
            _ATTACK,
            "modeled",
            "modeled cloud-object read permission at collection; data collection and current access unproven",
        )
    # AML.T0053 requires AI-agent tool invocation, not a tool listing. An exact
    # runtime reference identifies the recorded attempt, not successful abuse.
    # https://atlas.mitre.org/techniques/AML.T0053
    if (
        edge.relationship == RelationshipType.INVOKED
        and source.entity_type == EntityType.AGENT
        and target.entity_type == EntityType.TOOL
        and relationship_evidence_basis(edge) == "runtime_observed"
        and _runtime_state(edge) == "observed"
        and runtime_evidence_references(edge.evidence)
    ):
        return (
            "AML.T0053",
            _ATLAS,
            "runtime_observed",
            "runtime_observed agent tool invocation attempt; adversarial intent and outcome unproven",
        )
    # Generic vulnerability, exposure, credential reference, role assumption,
    # and tool inventory do not establish the prerequisites of a technique.
    return None


class TechniqueCatalogs:
    """Load each bundled/synced catalog at most once per annotation batch."""

    def __init__(self) -> None:
        self._attack: dict[str, dict] | None = None
        self._atlas: dict[str, dict] | None = None

    def attack(self) -> dict[str, dict]:
        if self._attack is None:
            from agent_bom.mitre_fetch import get_techniques

            self._attack = get_techniques()
        return self._attack

    def atlas(self) -> dict[str, dict]:
        if self._atlas is None:
            from agent_bom.atlas_fetch import get_techniques as atlas_techniques

            self._atlas = atlas_techniques()
        return self._atlas


def _attack_tactics(technique_id: str, catalogs: TechniqueCatalogs) -> list[str] | None:
    """Tactic phase names for an ATT&CK id, or ``None`` if not in the catalog."""
    meta = catalogs.attack().get(technique_id)
    if meta is None:
        return None
    return list(meta.get("tactics", []))


def _atlas_meta(technique_id: str, catalogs: TechniqueCatalogs) -> tuple[str, list[str]] | None:
    """``(name, tactic_ids)`` for a curated ATLAS id, or ``None`` if unknown."""
    from agent_bom.atlas import ATLAS_TECHNIQUES

    if technique_id not in ATLAS_TECHNIQUES:
        return None
    meta = catalogs.atlas().get(technique_id, {})
    name = meta.get("name") or ATLAS_TECHNIQUES.get(technique_id, "")
    return name, list(meta.get("tactics", []))


def derive_attack_path_techniques(
    path: AttackPath, graph: UnifiedGraph, catalogs: TechniqueCatalogs | None = None
) -> list[TechniqueMapping]:
    """Derive ordered, catalog-resolved technique mappings for ``path``.

    One mapping per hop that carries mappable evidence, in kill-chain order.
    Hops with no mappable evidence — or whose candidate technique does not
    resolve in the bundled catalog — are skipped (fail-closed). Never raises.
    """
    catalogs = catalogs or TechniqueCatalogs()
    mappings: list[TechniqueMapping] = []
    edges = path.edges or []
    hops = path.hops or []
    for i, rel_value in enumerate(edges):
        if i + 1 >= len(hops):
            break
        try:
            rel = RelationshipType(rel_value)
        except ValueError:
            continue
        if path.reachability in {"unknown", "unlikely"} and rel in _VULN_RELS:
            # ATT&CK/ATLAS annotate evidence-backed paths.  They must never
            # manufacture exploitability from structural topology.
            continue

        edge, _ = resolve_typed_hop(graph, hops[i], hops[i + 1], rel.value)
        if edge is None or not edge.traversable or edge.direction != "directed":
            continue
        candidate = _candidate(graph, edge)
        if candidate is None:
            continue
        technique_id, catalog, basis, provenance = candidate
        provenance += f"; edge {edge.canonical_id}"
        if catalog == _ATLAS:
            resolved = _atlas_meta(technique_id, catalogs)
            if resolved is None:
                continue  # dangling id — fail closed
            name, tactics = resolved
        else:
            tactics_or_none = _attack_tactics(technique_id, catalogs)
            if tactics_or_none is None:
                continue  # dangling id — fail closed
            name = str(catalogs.attack().get(technique_id, {}).get("name", ""))
            tactics = tactics_or_none
        mappings.append(
            TechniqueMapping(
                hop_index=i,
                technique_id=technique_id,
                technique_name=name,
                catalog=catalog,
                tactics=tactics,
                provenance=provenance,
                confidence=None,  # No calibrated technique-mapping score is available.
                evidence_basis=basis,
            )
        )
    return mappings


def apply_attack_path_technique_mappings(graph: UnifiedGraph) -> int:
    """Populate ``technique_mappings`` on every attack path in ``graph``.

    Idempotent: recomputes from the current evidence each call. Returns the
    number of mappings materialised. Never raises into the builder.
    """
    total = 0
    catalogs = TechniqueCatalogs()
    for path in graph.attack_paths:
        path.technique_mappings = derive_attack_path_techniques(path, graph, catalogs)
        total += len(path.technique_mappings)
    return total
