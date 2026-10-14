"""Edge evidence envelope: every edge names its ``source`` collector and ``tier``.

``tier`` says what kind of claim the collector makes (it read configuration, it
observed activity, it derived the edge from other edges). Tiers come from the
graph integration contract. ``legacy_unrecorded`` is how a reader classifies an
edge from a snapshot written before the envelope existed; loaders never write
it into stored evidence, because persisted content digests (correlation
manifests, remediation receipts) must survive a save/load round trip.

Producers that build evidence dicts by hand keep their collector name in
``source``; :func:`normalize_edge_evidence` fills ``tier`` from the collector
registry below. A collector absent from the registry gets no tier and the
relationship contract reports the edge, so a new collector cannot ship
unclassified.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.integration_contract import EVIDENCE_TIERS
from agent_bom.graph.relationship_specs import TraversalClass, relationship_spec

LEGACY_TIER = "legacy_unrecorded"
EDGE_EVIDENCE_TIERS = EVIDENCE_TIERS | {LEGACY_TIER}
# Tiers that need no further check (``derived`` must also name ``derived_via``).
_CLEAN_TIERS = EDGE_EVIDENCE_TIERS - {"derived"}

_MODELED = "modeled_infrastructure"
_STATIC = "static_scan"
_RECORDED = "recorded"
_RUNTIME = "runtime_observed"
_DERIVED = "derived"

# Collector name -> the tier of claim it makes. Configuration read from a
# provider API is modeled infrastructure; logs, audit trails and usage history
# are recorded observations; scanners reading files or manifests are static.
SOURCE_TIERS: dict[str, str] = {
    "cloud-inventory": _MODELED,
    "cloud_origin": _MODELED,
    "cloud_principal": _MODELED,
    "cloud_principal_trust": _MODELED,
    "cloud-rbac": _MODELED,
    "aws-organizations": _MODELED,
    "gcp-organizations": _MODELED,
    "ai-inventory": _MODELED,
    "snowflake-objects": _MODELED,
    "snowflake-services": _MODELED,
    "snowflake-organizations": _MODELED,
    "snowflake-pipeline": _MODELED,
    "snowflake-integrations": _MODELED,
    "snowflake-external-data": _MODELED,
    "snowflake-exfil": _MODELED,
    "snowflake-cortex-agents": _MODELED,
    "vendor-inventory-export": _MODELED,
    "cnapp-overlay": _MODELED,
    "nhi-discovery": _MODELED,
    "governance-overlay": _RECORDED,
    "hardware-attestation-ingest": _RECORDED,
    "access-advisor": _RECORDED,
    "authorization-evidence": _RECORDED,
    "cloud-audit-trail": _RECORDED,
    "cortex-agent-usage": _RECORDED,
    "mcp-audit": _RECORDED,
    "operator_reported_timestamps": _RECORDED,
    "snowflake-governance": _RECORDED,
    "tpm-quote": _RECORDED,
    "warehouse-export": _RECORDED,
    "runtime-feedback": _RUNTIME,
    "runtime-proxy": _RUNTIME,
    "runtime-identity": _RUNTIME,
    "snowflake-cortex-observability": _RUNTIME,
    "source-ast": _STATIC,
    "ast_analysis": _STATIC,
    "framework-agent": _STATIC,
    "agent_discovery": _STATIC,
    "mcp-scan": _STATIC,
    "skill-audit": _STATIC,
    "iac": _STATIC,
    "ci_graph_overlay": _STATIC,
    "code_graph_overlay": _STATIC,
    "github-actions": _STATIC,
    "repo-structure-overlay": _STATIC,
    "repo-trust-overlay": _STATIC,
    "aspm-overlay": _STATIC,
}

# Collector-name prefixes for families whose names carry a variant suffix.
_SOURCE_PREFIX_TIERS: tuple[tuple[str, str], ...] = (("warehouse-export:", _RECORDED),)


def tier_for_source(source: object) -> str | None:
    if not isinstance(source, str) or not source:
        return None
    tier = SOURCE_TIERS.get(source)
    if tier is not None:
        return tier
    for prefix, prefix_tier in _SOURCE_PREFIX_TIERS:
        if source.startswith(prefix):
            return prefix_tier
    return None


def edge_evidence(source: str, tier: str, basis: str | None = None, **extra: Any) -> dict[str, Any]:
    """Build an edge evidence dict with the required ``source`` and ``tier``.

    A ``derived`` edge must name what it was derived from (``derived_via``) so a
    reader can walk back to the observed evidence.
    """
    if not source:
        raise ValueError("edge evidence requires a source")
    if tier not in EDGE_EVIDENCE_TIERS:
        raise ValueError(f"unknown edge evidence tier: {tier!r}")
    if tier == _DERIVED and not extra.get("derived_via"):
        raise ValueError("derived edge evidence requires derived_via")
    evidence: dict[str, Any] = {"source": source, "tier": tier}
    if basis:
        evidence["basis"] = basis
    evidence.update({key: value for key, value in extra.items() if value is not None})
    return evidence


def normalize_edge_evidence(evidence: dict[str, Any], provenance: dict[str, Any] | None = None) -> None:
    """Fill ``tier`` from the collector registry; ``source`` falls back to the
    edge's ``data_source`` or provenance collector when the producer kept it there."""
    if "source" not in evidence:
        for fallback in (evidence.get("data_source"), (provenance or {}).get("source")):
            if isinstance(fallback, str) and fallback:
                evidence["source"] = fallback
                break
    if "tier" not in evidence:
        tier = tier_for_source(evidence.get("source"))
        if tier is not None:
            evidence["tier"] = tier


def recorded_tier(evidence: dict[str, Any] | None) -> str:
    """The edge's recorded tier, or ``legacy_unrecorded`` for a pre-envelope edge."""
    tier = (evidence or {}).get("tier")
    return tier if isinstance(tier, str) and tier in EDGE_EVIDENCE_TIERS else LEGACY_TIER


def evidence_problems(evidence: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    tier = evidence.get("tier")
    if tier in _CLEAN_TIERS and all(evidence.get(key) not in (None, "", [], {}) for key in required):
        return []
    problems = [f"missing_evidence_{key}" for key in required if evidence.get(key) in (None, "", [], {})]
    tier = evidence.get("tier")
    if tier not in (None, "") and tier not in EDGE_EVIDENCE_TIERS:
        problems.append("unknown_evidence_tier")
    if tier == _DERIVED and not evidence.get("derived_via"):
        problems.append("derived_without_derived_via")
    return problems


def merge_edge_provenance(stored: Any, incoming: Any) -> None:
    """Union provenance sources and keep the strongest confidence on re-add."""
    if incoming.confidence > stored.confidence:
        stored.confidence = incoming.confidence
    if not incoming.provenance:
        return
    sources: list[str] = []
    for prov in (stored.provenance, incoming.provenance):
        for value in (prov.get("source"), *(prov.get("sources") or ())):
            if isinstance(value, str) and value and value not in sources:
                sources.append(value)
    for key, value in incoming.provenance.items():
        if key not in stored.provenance or stored.provenance[key] in (None, "", [], {}):
            stored.provenance[key] = value
    if len(sources) > 1:
        stored.provenance["sources"] = sources


def fixture_edge_evidence(rel: Any, source: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evidence for hand-authored (demo / fixture) edges: tier follows the edge kind.

    Findings are scanner claims, runtime kinds are recorded activity, and every
    other kind describes modeled inventory. An explicit ``tier`` wins.
    """
    spec = relationship_spec(rel)
    tiers = {TraversalClass.FINDING: _STATIC, TraversalClass.RUNTIME: _RECORDED}
    tier = tiers.get(spec.traversal_class, _MODELED) if spec is not None else _MODELED
    result = dict(evidence or {})
    result.setdefault("source", source)
    result.setdefault("tier", tier)
    return result
