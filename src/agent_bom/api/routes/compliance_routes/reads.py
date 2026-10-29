"""Narrative, posture and compliance-hub read routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api import read_models
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING as _HUB_LIST_OFFSET_CEILING
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.compliance import (
    AisvsComplianceResponse,
    BackpressurePostureResponse,
    ComplianceVerificationKeyResponse,
    CredentialRiskRankingResponse,
    EnrichmentPostureResponse,
    HubFindingsResponse,
    IncidentCorrelationResponse,
)
from agent_bom.api.routes.compliance_routes.common import (
    SEEDING_GUARD,
    _credential_rotation_governance,
    _current_narrative_evidence,
    _latest_aisvs_benchmark_from_jobs,
    _native_hub_findings,
    _posture_scorecard_impl,
    _tenant_id,
    _tenant_jobs,
    cached_tenant_read,
)
from agent_bom.api.routes.compliance_routes.evidence import _narrative_to_dict
from agent_bom.api.routes.compliance_routes.hub_paging import _cursor_walk_page, _decode_hub_list_cursor, _unpack_hub_list_page
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.evidence import EvidenceTier, redact_for_persistence

if TYPE_CHECKING:
    from agent_bom.output.compliance_narrative import ComplianceNarrative

narrative_router = APIRouter()
posture_router = APIRouter()
posture_detail_router = APIRouter()
hub_router = APIRouter()


@narrative_router.get("/compliance/narrative", **read_models.documented(read_models.ComplianceNarrativeResponse), tags=["compliance"])
def get_compliance_narrative(request: Request) -> dict:
    """Generate a review-ready compliance narrative from current tenant evidence.

    Produces human-readable stories for all supported framework mappings, a
    cross-framework executive summary, and a remediation-compliance bridge
    showing which package upgrades resolve which controls.

    No LLM is required — narratives are generated from template strings and
    the canonical current finding queue used by the REST/CLI/UI surfaces.
    """
    from agent_bom.output.compliance_narrative import COMPLIANCE_CLAIM_BOUNDARY

    evidence = _current_narrative_evidence(request)
    if evidence is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
            "claim_boundary": COMPLIANCE_CLAIM_BOUNDARY,
        }

    from agent_bom.output.compliance_narrative import generate_compliance_narrative_from_findings

    narrative: ComplianceNarrative = generate_compliance_narrative_from_findings(
        evidence["findings"],
        total_agents=evidence["total_agents"],
        total_packages=evidence["total_packages"],
        generated_at=evidence["generated_at"],
    )
    return _narrative_to_dict(narrative, evidence=evidence)


@narrative_router.get("/compliance/narrative/{framework}", **documented(read_models.ComplianceNarrativeResponse), tags=["compliance"])
def get_compliance_narrative_by_framework(request: Request, framework: str) -> dict:
    """Generate a single-framework compliance narrative.

    Supported framework slugs: owasp-llm, owasp-mcp, atlas, nist,
    owasp-agentic, eu-ai-act, nist-csf, iso-27001, soc2, cis, cmmc.

    Returns the same structure as GET /v1/compliance/narrative but scoped
    to a single framework's controls.
    """
    from agent_bom.compliance_coverage import normalize_framework_slug
    from agent_bom.output.compliance_narrative import (
        ALL_FRAMEWORK_SLUGS,
        COMPLIANCE_CLAIM_BOUNDARY,
    )

    canonical = normalize_framework_slug(framework)
    if canonical not in ALL_FRAMEWORK_SLUGS:
        raise HTTPException(
            status_code=400,
            detail=(f"Unknown framework '{framework}'. Supported: {', '.join(ALL_FRAMEWORK_SLUGS)}"),
        )

    evidence = _current_narrative_evidence(request)
    if evidence is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
            "claim_boundary": COMPLIANCE_CLAIM_BOUNDARY,
        }

    from agent_bom.output.compliance_narrative import generate_compliance_narrative_from_findings

    narrative: ComplianceNarrative = generate_compliance_narrative_from_findings(
        evidence["findings"],
        total_agents=evidence["total_agents"],
        total_packages=evidence["total_packages"],
        generated_at=evidence["generated_at"],
        framework=canonical,
    )
    return _narrative_to_dict(narrative, evidence=evidence)


@narrative_router.get("/compliance/verification-key", **documented(ComplianceVerificationKeyResponse), tags=["compliance"])
def get_compliance_verification_key(request: Request) -> dict:
    """Return the key material — and the verifiability posture — for evidence bundles.

    Safe to expose: the only key it can return is a public key. Auditors and
    external SIEM systems use this endpoint to fetch the verification key
    without operator hand-off.

    It answers "can I verify a bundle from this deployment?", not just "which
    algorithm was used". By default ``agent-bom serve`` has no
    ``AGENT_BOM_AUDIT_HMAC_KEY``, so the HMAC key is generated per-process and
    never leaves it — bundles signed with it are unverifiable by anyone, and
    reporting only ``algorithm: HMAC-SHA256`` sent auditors after a key that
    does not exist.

    Response shape:
      - ``algorithm``: "Ed25519" when asymmetric signing is configured, else "HMAC-SHA256"
      - ``signature_verifiable``: whether ANY verifier can check a bundle from this deployment
      - ``persists_across_restart``: whether the signing key survives a restart
      - ``verification_status``: verifiable_public_key | verifiable_shared_secret | unverifiable_ephemeral_key
      - ``remediation``: operator action to make evidence verifiable, or null when it already is
      - ``key_id``: stable 16-hex prefix of SHA-256(DER public key) — identifies the key across rotations
      - ``public_key_pem``: PEM-encoded public key (Ed25519 only)
      - ``key_distribution``: guidance for verifiers
    """
    from agent_bom.api.compliance_signing import describe_signer_disclosure

    disclosure = describe_signer_disclosure()
    return {
        "algorithm": disclosure.algorithm,
        "key_id": disclosure.key_id,
        "public_key_pem": disclosure.public_key_pem,
        "signature_verifiable": disclosure.signature_verifiable,
        "persists_across_restart": disclosure.persists_across_restart,
        "verification_status": disclosure.verification_status,
        "remediation": disclosure.remediation,
        "key_distribution": disclosure.verification_guidance,
    }


@narrative_router.get("/compliance/aisvs", **documented(AisvsComplianceResponse), tags=["compliance"])
def get_aisvs_compliance(request: Request) -> dict:
    """Return the latest tenant-scoped OWASP AISVS benchmark result from completed scans."""
    return _latest_aisvs_benchmark_from_jobs(_tenant_jobs(request))


@posture_router.get("/posture", **read_models.documented(read_models.PostureResponse), tags=["compliance"], dependencies=[SEEDING_GUARD])
async def get_posture_scorecard(request: Request) -> dict:
    """Compute enterprise posture scorecard from the latest completed scan.

    Returns a letter grade (A-F), numeric score (0-100), and per-dimension
    breakdown covering vulnerability posture, credential hygiene, supply
    chain quality, compliance coverage, active exploitation, and configuration.
    """
    return await anyio.to_thread.run_sync(_cached_posture_scorecard, request)


def _cached_posture_scorecard(request: Request) -> dict:
    return cached_tenant_read(request, "posture", (), lambda: _posture_scorecard_impl(request))


@posture_router.get("/posture/enrichment", **documented(EnrichmentPostureResponse), tags=["compliance"])
def get_enrichment_posture() -> dict:
    """Report runtime health for external vulnerability enrichment sources."""

    from agent_bom.enrichment_posture import describe_enrichment_posture

    return describe_enrichment_posture()


@posture_router.get("/posture/backpressure", **documented(BackpressurePostureResponse), tags=["compliance"], deprecated=True)
def get_backpressure_posture() -> dict:
    """Report adaptive runtime backpressure state for expensive paths.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """

    from agent_bom.backpressure import describe_backpressure_posture

    return describe_backpressure_posture()


@posture_detail_router.get("/posture/credentials", **documented(CredentialRiskRankingResponse), tags=["compliance"])
def get_credential_risk_ranking(request: Request) -> dict:
    """Rank credentials by blast radius exposure from the latest scan.

    Returns credentials sorted by risk tier (critical to low) with
    associated vulnerability counts and affected agents.
    """
    tenant_id = _tenant_id(request)
    rotation_governance = _credential_rotation_governance(tenant_id)
    latest_result = None
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"credentials": [], "count": 0, "rotation_governance": rotation_governance}

    ranking = latest_result.get("credential_risk_ranking", [])
    return {"credentials": ranking, "count": len(ranking), "rotation_governance": rotation_governance}


@posture_detail_router.get("/posture/incidents", **documented(IncidentCorrelationResponse), tags=["compliance"])
def get_incident_correlation(request: Request) -> dict:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns agent-centric incident summaries with priority (P1-P4),
    severity counts, credential exposure, and recommended actions.
    """
    latest_result = None
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"incidents": [], "count": 0}

    incidents = latest_result.get("incident_correlation", [])
    incidents = redact_for_persistence(incidents, EvidenceTier.SAFE_TO_STORE)
    return {"incidents": incidents, "count": len(incidents)}


@hub_router.get("/compliance/hub/findings", **documented(HubFindingsResponse), tags=["compliance"])
async def list_hub_findings(request: Request, limit: int = Query(200, ge=1, le=1000), offset: int = 0, cursor: str | None = None) -> dict:
    """List compliance-hub findings for the current tenant.

    Returns the canonical finding-list envelope (#3666) shared with
    ``/v1/findings`` so consumers learn one shape across every finding surface.
    Includes durable external ingests plus native scan findings projected into
    the same shape so the list endpoint matches `/hub/posture` totals.

    Ordering is ingest-order (``sort="ordinal"``) so the list matches the way
    findings were imported. ``cursor`` is the scale path: it walks the native
    scan prefix and the durable hub store with a bounded opaque continuation,
    then uses the indexed ``(ledger_ordinal, first_seen, canonical_id)`` keyset.
    ``limit`` / ``offset`` remain as a compatibility path capped at offset
    10,000; deeper walks must follow ``next_cursor``.

    The synchronous store read (page fetch + count) runs in a worker thread
    under adaptive backpressure so a deep page against a large tenant cannot
    block the event loop and starve ``/health`` (mirrors ``/v1/findings``);
    under saturation it sheds with ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_list_hub_findings_impl, request, limit, offset, cursor)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except ValueError as exc:
        detail = "Invalid or stale compliance hub cursor" if cursor else "Invalid compliance hub pagination"
        raise HTTPException(status_code=400, detail=detail) from exc


def _list_hub_findings_impl(request: Request, limit: int, offset: int, cursor: str | None = None) -> dict:
    """Synchronous body of :func:`list_hub_findings` (runs in a worker thread)."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.finding_list_envelope import finding_list_envelope

    tenant_id = _tenant_id(request)
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)
    if safe_offset > _HUB_LIST_OFFSET_CEILING:
        raise ValueError("offset exceeds compatibility ceiling; use cursor")
    if cursor and safe_offset:
        raise ValueError("cursor and offset cannot be combined")
    sort = "ordinal"
    native = _native_hub_findings(request)

    # Validate the opaque continuation before resolving the store. Malformed,
    # cross-tenant, or stale-native cursors therefore perform no database work.
    if cursor:
        native_index, hub_cursor, stable_total = _decode_hub_list_cursor(
            cursor,
            tenant_id=tenant_id,
            native_findings=native,
        )
    else:
        native_index, hub_cursor, stable_total = 0, "", -1

    store = get_compliance_hub_store()
    list_page = getattr(store, "list_current_page", None) or getattr(store, "list_page", None)
    if not callable(list_page):
        if cursor:
            raise ValueError("cursor pagination requires a paged compliance store")
        findings = store.list(tenant_id) + native
        page = findings[safe_offset : safe_offset + safe_limit]
        total = len(findings)
        next_cursor = ""
    elif safe_offset:
        # Backward-compatible, explicitly bounded OFFSET behavior. New clients
        # use cursor and never issue an OFFSET against the durable store.
        window = safe_offset + safe_limit
        legacy_hub_rows, legacy_hub_total, _ = _unpack_hub_list_page(list_page(tenant_id, limit=window, offset=0, sort=sort))
        combined = native + legacy_hub_rows
        page = combined[safe_offset : safe_offset + safe_limit]
        total = len(native) + int(legacy_hub_total or 0)
        next_cursor = ""
    else:
        page, total, next_cursor = _cursor_walk_page(
            list_page,
            tenant_id=tenant_id,
            native=native,
            native_index=native_index,
            hub_cursor=hub_cursor,
            stable_total=stable_total,
            safe_limit=safe_limit,
            sort=sort,
            cursor=cursor,
        )
    return finding_list_envelope(
        findings=page,
        # A continuation is not a database snapshot: concurrent ingests may
        # change the matching cardinality between pages. Return null instead of
        # replaying a potentially stale first-page COUNT as if it were exact.
        total=None if cursor else total,
        limit=safe_limit,
        offset=safe_offset,
        sort=sort,
        cursor=cursor or "",
        next_cursor=next_cursor,
        source="native_and_compliance_hub_findings",
        scope="tenant compliance-hub current findings",
    )
