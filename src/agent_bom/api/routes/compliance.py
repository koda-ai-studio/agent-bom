"""Compliance narratives, framework evidence and tenant posture read routes.

This module owns ``router`` and the routes whose collaborators tests patch here
(``_tenant_jobs``, ``_build_compliance``, the posture/hub ``*_impl`` helpers).
The remaining routes and the evidence helpers live in
:mod:`agent_bom.api.routes.compliance_routes` and are included below in the
original registration order.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, cast

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from agent_bom.api import read_models
from agent_bom.api.finding_read_context import finding_read_snapshot
from agent_bom.api.hub_ingest import read_compliance_ingest_body
from agent_bom.api.models import ComplianceReportBundle, JobStatus
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.compliance import (
    ComplianceEvidencePackResponse,
    ComplianceSummaryResponse,
    FrameworkComplianceResponse,
    Nist80053DrillResponse,
)
from agent_bom.api.routes.compliance_routes import cis, reads
from agent_bom.api.routes.compliance_routes.bundle import (
    _attach_signer_key,
    _audit_window,
    _bundle_signing_headers,
    _bundle_threat_model,
    _detective_pass_count,
    _enrich_controls_with_evidence,
    _index_blast_radii_by_tag,
    _jsonl_bundle_payload,
    _ndjson_attachment,
    _pack_framework_bundles,
    _parse_iso_or_default,
)
from agent_bom.api.routes.compliance_routes.cis import list_cis_benchmark_checks as list_cis_benchmark_checks
from agent_bom.api.routes.compliance_routes.common import _POSTURE_COUNTS_CACHE as _POSTURE_COUNTS_CACHE
from agent_bom.api.routes.compliance_routes.common import _cached_issue_severity_counts as _cached_issue_severity_counts
from agent_bom.api.routes.compliance_routes.common import (
    _compliance_evidence_authority_key,
    _get_hub_posture_impl,
    _get_posture_counts_impl,
    _latest_aisvs_benchmark_from_jobs,
    _tenant_id,
    _tenant_jobs,
    framework_posture_with_count,
)
from agent_bom.api.routes.compliance_routes.common import _derive_deployment_context as _derive_deployment_context
from agent_bom.api.routes.compliance_routes.common import estate_agent_count as estate_agent_count
from agent_bom.api.routes.compliance_routes.evidence import (
    _aggregate_cis_foundations_checks,
    _build_cis_foundations_line,
    _result_compliance_evidence,
    _result_evidence_context,
)
from agent_bom.api.routes.compliance_routes.evidence import _bucket_for as _bucket_for
from agent_bom.api.routes.compliance_routes.evidence import _coerce_cis_row as _coerce_cis_row
from agent_bom.api.routes.compliance_routes.evidence import _narrative_to_dict as _narrative_to_dict
from agent_bom.api.routes.compliance_routes.evidence import _result_has_runtime_signals as _result_has_runtime_signals
from agent_bom.api.routes.compliance_routes.reads import get_aisvs_compliance
from agent_bom.api.routes.compliance_routes.reads import get_compliance_narrative as get_compliance_narrative
from agent_bom.api.routes.compliance_routes.reads import get_credential_risk_ranking as get_credential_risk_ranking
from agent_bom.api.routes.compliance_routes.reads import get_incident_correlation as get_incident_correlation
from agent_bom.api.routes.compliance_routes.reads import get_posture_scorecard as get_posture_scorecard
from agent_bom.api.routes.compliance_routes.scoring import (
    _build_framework_controls,
    _compliance_verdict,
    _framework_status_summary,
    _framework_summary_from,
    _total_control_count,
)
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.compliance_nist_catalog import build_nist_800_53_catalog_line, build_nist_800_53_drill
from agent_bom.compliance_nist_catalog import evaluated_control_status as _evaluated_control_status  # noqa: F401
from agent_bom.evidence.detective_evidence import DetectiveScanEvidence
from agent_bom.evidence.scoring import score_compliance
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


router = APIRouter(dependencies=[_dep("read")])
_logger = logging.getLogger(__name__)

# Cap on audit entries pulled into a single signed evidence bundle. When the
# window holds more than this the bundle marks itself truncated (honest partial
# evidence) rather than silently presenting the capped set as the complete
# window; consumers paginate the full trail via /v1/audit.
_AUDIT_EVIDENCE_FETCH_LIMIT = 10_000


@router.get("/compliance", **read_models.documented(read_models.ComplianceResponse), tags=["compliance"])
async def get_compliance(
    request: Request,
    scan_id: Annotated[str | None, Query(max_length=200)] = None,
) -> dict:
    """Aggregate OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF,
    OWASP Agentic Top 10, and EU AI Act compliance posture across all completed scans.

    Returns scored control posture plus applicability-only risk/technique
    catalogs and an overall score derived only from the scored frameworks.
    """
    return await anyio.to_thread.run_sync(_compliance_for_request, request, scan_id)


@finding_read_snapshot
def _compliance_for_request(request: Request, scan_id: str | None) -> dict[str, Any]:
    return _build_compliance(jobs := _tenant_jobs(request), scan_id=scan_id, cis_graph=cis.current_cis_graph(request, scan_id, jobs))


def _build_compliance(tenant_jobs: list[Any], *, scan_id: str | None = None, cis_graph: cis.GraphCisState | None = None) -> dict[str, Any]:
    """Build compliance truth from one caller-owned job-store snapshot."""
    from agent_bom.api.findings_current import current_scan_jobs, scan_evidence_authority_key
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    tenant_jobs = list(
        current_scan_jobs(
            tenant_jobs,
            since=None,
            scan_id=scan_id,
            require_authoritative_evidence=True,
        )
    )

    # Collect the unified findings spine (legacy blast-radius fallback) from all
    # completed scans, deduped by canonical occurrence identity across re-scans.
    all_blast: list[dict] = []
    authoritative_occurrences: dict[str, tuple[tuple[str, str, str], dict[str, Any]]] = {}
    latest_scan_job: Any | None = None
    has_mcp_context = False
    has_agent_context = False
    all_scan_sources: set[str] = set()

    completed_jobs = [job for job in tenant_jobs if job.status == JobStatus.DONE and job.result]
    scan_count = len(completed_jobs)
    for job in completed_jobs:
        for row in _result_compliance_evidence(job.result):
            occurrence_id = str(row.get("id") or row.get("canonical_id") or "")
            if not occurrence_id:
                all_blast.append(row)
                continue
            authority = _compliance_evidence_authority_key(job, row)
            current = authoritative_occurrences.get(occurrence_id)
            if current is None or authority > current[0]:
                authoritative_occurrences[occurrence_id] = (authority, row)
        if latest_scan_job is None or scan_evidence_authority_key(job) > scan_evidence_authority_key(latest_scan_job):
            latest_scan_job = job
        # Detect scan context from result metadata
        result_has_mcp, result_has_agent, result_sources = _result_evidence_context(job.result)
        has_mcp_context = has_mcp_context or result_has_mcp
        has_agent_context = has_agent_context or result_has_agent
        all_scan_sources.update(result_sources)

    all_blast.extend(row for _authority, row in authoritative_occurrences.values())
    latest_scan = getattr(latest_scan_job, "completed_at", None) if latest_scan_job is not None else None
    # Detective controls rest only on scans whose lane ran, and a partial vulnerability lane withholds their pass.
    scan_evidence = DetectiveScanEvidence.for_results(((job.result, job.completed_at) for job in completed_jobs), latest_scan=latest_scan)

    framework_controls = _build_framework_controls(
        all_blast,
        TAG_MAPPED_FRAMEWORKS,
        scan_count=scan_count,
        latest_scan=latest_scan,
        vulnerability_coverage_incomplete=scan_evidence.vulnerability_coverage_incomplete,
        scan_evidence=scan_evidence,
    )

    # Wire the CIS Foundations Benchmark posture (report.cis_benchmark_data + the
    # azure/gcp/snowflake/databricks siblings) into the aggregate. Previously the
    # scorecard derived every status ONLY from CVE-tag data, so a cloud account
    # failing CIS controls read green/no_data. The benchmark is a DIFFERENT
    # taxonomy than the CVE-driven CIS Controls v8 line, kept as its own labeled
    # line below; here we only fold its pass/fail/error into the top-line so a
    # failing CIS account can't read as compliant. ERROR is unevaluable — counted
    # toward the evaluated denominator (drags the score down) but never the
    # numerator.
    cis_foundations_agg = _aggregate_cis_foundations_checks(tenant_jobs, cis_graph)
    aisvs = _latest_aisvs_benchmark_from_jobs(tenant_jobs)
    aisvs_summary = aisvs["summary"]
    total_controls = _total_control_count(TAG_MAPPED_FRAMEWORKS, cis_foundations_agg, aisvs_summary)
    verdict = _compliance_verdict(framework_controls, TAG_MAPPED_FRAMEWORKS, cis_foundations_agg, aisvs_summary, scan_count)
    evaluated_controls = verdict.evaluated
    coverage_pct = round((evaluated_controls / total_controls) * 100, 2) if total_controls > 0 else 0.0

    cis_foundations_line = _build_cis_foundations_line(cis_foundations_agg)
    # PR3: catalog-backed NIST 800-53 line, scored INDEPENDENTLY over evaluated
    # controls only (curated check -> control map). Deliberately NOT folded into
    # overall_score/overall_status — the same CVE/CIS evidence already drives the
    # existing per-framework lines, so folding would double-count.
    nist_800_53_catalog_line = build_nist_800_53_catalog_line(
        all_blast,
        cis_foundations_agg.get("statuses", {}),
        scan_count,
    )
    summary = _framework_status_summary(
        framework_controls, TAG_MAPPED_FRAMEWORKS, aisvs_summary, cis_foundations_line, nist_800_53_catalog_line
    )

    response: dict[str, Any] = {
        "overall_score": verdict.score,
        "overall_status": verdict.status,
        # Denominator context for overall_score — never render the percentage
        # without it (see the comment where these are computed).
        "evaluated_controls": evaluated_controls,
        "total_controls": total_controls,
        "coverage_pct": coverage_pct,
        "scan_count": scan_count,
        "latest_scan": latest_scan,
        "has_mcp_context": has_mcp_context,
        "has_agent_context": has_agent_context,
        "scan_sources": sorted(all_scan_sources),
        # Serialized measurement contract for every framework. Consumers must
        # not infer this from labels: OWASP risk catalogs and MITRE technique
        # catalogs are applicability overlays, never pass/fail controls.
        "framework_kinds": {metadata.output_key: ("scored" if metadata.scored else "applicability") for metadata in TAG_MAPPED_FRAMEWORKS},
        "aisvs_benchmark": aisvs,
        "cis_foundations_benchmark": cis_foundations_line,
        "nist_800_53_catalog": nist_800_53_catalog_line,
        "summary": summary,
    }
    for metadata in TAG_MAPPED_FRAMEWORKS:
        response[metadata.output_key] = framework_controls[metadata.output_key]
    return response


router.include_router(cis.router)
router.include_router(reads.narrative_router)


@router.get("/compliance/summary", **documented(ComplianceSummaryResponse), tags=["compliance"])
async def get_compliance_summary(request: Request) -> dict:
    """Return aggregate compliance score and per-framework status counts.

    Keep this literal route above /v1/compliance/{framework}; otherwise FastAPI
    correctly treats "summary" as a framework slug.
    """
    full = await get_compliance(request)
    summary_keys = {
        "overall_score",
        "overall_status",
        # overall_score is a percentage of EVALUATED controls, so its
        # denominator travels with it on every surface that renders it (see the
        # comment where these are computed in get_compliance). Omitting them
        # here left the Overview rendering a bare percentage it could not
        # qualify.
        "evaluated_controls",
        "total_controls",
        "scan_count",
        "latest_scan",
        "has_mcp_context",
        "has_agent_context",
        "scan_sources",
        "summary",
    }
    response = {key: full.get(key) for key in summary_keys if key in full}

    # With zero completed scans nothing was evaluated: every control trivially
    # lacks findings, so the per-control "pass" statuses and the *_pass counts
    # from get_compliance would read as all-pass / fully compliant. That is the
    # same false assurance /v1/compliance guards against with overall_status=
    # "no_data" — so mirror it here and report not_evaluated instead of pass.
    no_data = int(full.get("scan_count") or 0) == 0

    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    overlay_keys = {metadata.output_key for metadata in TAG_MAPPED_FRAMEWORKS if not metadata.scored}

    response["frameworks"] = _framework_summary_from(full, overlay_keys, no_data)

    # When no_data the aggregate (get_compliance) already emits 0 pass/warn/fail
    # and a per-framework *_not_evaluated count equal to the catalogue size, so
    # the pass-through summary above is already honest — no reinterpretation
    # needed here.

    return response


@router.get("/compliance/nist-800-53", **documented(Nist80053DrillResponse), tags=["compliance"])
async def get_compliance_nist_800_53(
    request: Request,
    status: str | None = None,
    include_not_evaluated: bool = False,
) -> dict:
    """Drill the catalog-backed NIST SP 800-53 Rev 5 line.

    Returns per-control status (pass / fail / error / not_evaluated), the
    vendor-asserted evidencing checks behind each evaluated control, a family
    rollup for scale-aware navigation, and the ISO/IEC 27001 attribution derived
    BY ID from NIST's official SP 800-53 → ISO crosswalk (identifiers only; no
    copyrighted ISO title text).

    The headline ``summary``/``score``/``status`` are the SAME values the
    ``/v1/compliance`` ``nist_800_53_catalog`` line reports (one source of
    truth). By default only EVALUATED controls are listed — the ~1000-control
    ``not_evaluated`` remainder is a count, not a mile-long tower. Pass
    ``include_not_evaluated=true`` to enumerate the full catalog; ``status=``
    (comma-separated) filters the displayed control list WITHOUT changing the
    counts. Declared before ``/compliance/{framework}`` so FastAPI does not treat
    ``nist-800-53`` as a tag-mapped framework slug.
    """
    full = await get_compliance(request)
    return build_nist_800_53_drill(
        full["nist_800_53_catalog"],
        status=status,
        include_not_evaluated=include_not_evaluated,
    )


@router.get("/compliance/{framework}", **documented(FrameworkComplianceResponse), tags=["compliance"])
async def get_compliance_by_framework(request: Request, framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act,
    nist-csf, iso-27001, soc2, cis, cmmc, aisvs
    """
    if framework.lower() == "aisvs":
        return get_aisvs_compliance(request)

    full = await get_compliance(request)

    from agent_bom.compliance_coverage import framework_output_key_by_slug, normalize_framework_slug

    framework_map = framework_output_key_by_slug()

    canonical = normalize_framework_slug(framework)
    key = framework_map.get(canonical)
    if not key:
        supported = [*framework_map.keys(), "aisvs"]
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(supported)}",
        )

    controls = full.get(key, [])
    # With zero completed scans every control trivially "passes" (no findings map
    # to it), so reporting score 100 / "fully compliant" is compliance theater.
    # Detect it from the aggregate's scan_count — the same no_data signal the
    # summary endpoint uses — and surface an explicit no_data status instead.
    no_data = int(full.get("scan_count") or 0) == 0
    return await framework_posture_with_count(request, framework, canonical, controls, no_data=no_data)


@router.get("/compliance/{framework}/report", tags=["compliance"], response_model=ComplianceReportBundle)
def export_compliance_report(
    request: Request,
    framework: str,
    since: str | None = None,
    until: str | None = None,
    format: str = "json",
) -> JSONResponse | PlainTextResponse | StreamingResponse:
    """Export a tamper-evident signed evidence bundle for a single framework.

    The bundle pairs each control with the blast-radius findings that map to
    its tags, the audit-log entries within the requested time window, and
    integrity totals from the HMAC-chained log.

    Security properties of the bundle:

    - **Integrity** — ``X-Agent-Bom-Compliance-Report-Signature`` is the
      HMAC-SHA256 of the canonical body. Any tampering with any field
      invalidates the signature.
    - **Replay protection** — the body carries ``nonce`` (128-bit) and
      ``expires_at``; both are inside the signed envelope so a captured
      bundle cannot be re-used after its expiry window. Consumers should
      reject bundles where ``expires_at`` is in the past.
    - **Confidentiality** — the bundle is cleartext at the application
      layer by design (auditors need to read it). Operators MUST serve
      ``/v1/compliance/*`` over TLS so evidence is not sniffable in
      transit.
    - **Non-repudiation** — HMAC is a shared secret so it does not provide
      true non-repudiation; for forensic use, correlate with the
      ``compliance.report_exported`` entry in the audit log (which
      records the nonce of every exported bundle).
    - **Tenant isolation** — controls evidence and audit events are
      filtered by the authed tenant; cross-tenant data never appears
      in a bundle belonging to another tenant.

    Query params:
      - ``since`` ISO-8601 timestamp (default: now − 30 days)
      - ``until`` ISO-8601 timestamp (default: now)
      - ``format`` ``json`` (default) or ``jsonl`` for streaming consumers
    """
    fmt = format.lower()
    if fmt not in {"json", "jsonl"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, jsonl")

    now = datetime.now(timezone.utc)
    since_dt = _parse_iso_or_default(since, now - timedelta(days=30))
    until_dt = _parse_iso_or_default(until, now)
    if since_dt >= until_dt:
        raise HTTPException(status_code=400, detail="since must be earlier than until")

    raw_tenant_jobs = _tenant_jobs(request)
    full = _build_compliance(raw_tenant_jobs)
    from agent_bom.compliance_coverage import framework_report_labels_by_slug

    framework_map = framework_report_labels_by_slug()
    key_label = framework_map.get(framework.lower())
    if not key_label:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(framework_map.keys())}",
        )
    framework_key, framework_label = key_label
    controls = full.get(framework_key, [])

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    from agent_bom.api.findings_current import current_scan_jobs

    tenant_jobs = list(
        current_scan_jobs(
            raw_tenant_jobs,
            since=None,
            scan_id=None,
            require_authoritative_evidence=True,
        )
    )
    blast_by_tag = _index_blast_radii_by_tag(tenant_jobs)

    from agent_bom.api.audit_log import get_audit_log, log_action

    # Cap audit fetch for export sanity; consumers paginate further via /v1/audit.
    audit_fetch_limit = _AUDIT_EVIDENCE_FETCH_LIMIT
    audit_in_window, audit_truncated, verified, tampered = _audit_window(
        get_audit_log(), since_dt, until_dt, tenant_id=tenant_id, fetch_limit=audit_fetch_limit
    )

    completed_scan_count = sum(1 for job in tenant_jobs if job.status == JobStatus.DONE and bool(job.result))
    enriched_controls, evidence_row_count, distinct_finding_ids, status_counts = _enrich_controls_with_evidence(
        controls,
        blast_by_tag,
        completed_scan_count=completed_scan_count,
    )
    pass_count = status_counts["pass"]
    warn_count = status_counts["warning"]
    fail_count = status_counts["fail"]
    incomplete_count = status_counts["incomplete"]
    not_evaluated_count = status_counts["not_evaluated"]

    # An applicability overlay (ATT&CK) has no pass rate: a score would read as
    # "0% of ATT&CK passing" for something that cannot pass. Null says so — the
    # applicable counters carry the signal. Matches the evidence pack, which
    # already nulls the score for a scored=False framework.
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    bundle_scored = next((m.scored for m in TAG_MAPPED_FRAMEWORKS if m.output_key == framework_key), True)
    # Same scorer as every other surface; the detective passes it discounts are
    # the ones the bundle now preserves rather than downgrading to incomplete.
    bundle_verdict = score_compliance(
        passed=pass_count,
        warned=warn_count,
        failed=fail_count,
        detective_passes=_detective_pass_count(controls, pass_count),
        has_evidence=completed_scan_count > 0,
    )

    # Replay-protection envelope: every bundle carries a fresh 128-bit nonce
    # and an explicit expiry. The signature is computed over the canonical
    # body that includes both, so tampering with either invalidates the
    # signature and a captured bundle cannot be re-used after expiry.
    nonce = secrets.token_hex(16)
    bundle_ttl_seconds = int(os.environ.get("AGENT_BOM_COMPLIANCE_BUNDLE_TTL_SECONDS", "86400"))
    bundle_ttl_seconds = max(60, min(bundle_ttl_seconds, 30 * 86400))  # 1 min to 30 days
    expires_at = now + timedelta(seconds=bundle_ttl_seconds)

    # Resolve signer config up-front so the algorithm, key_id, and public key
    # are part of the canonical body that gets signed — verifiers read the
    # same fields and reconstruct the exact canonical form.
    from agent_bom.api.compliance_signing import (
        canonical_bundle_payload,
        describe_signer_disclosure,
        sign_compliance_bundle,
    )

    signer = describe_signer_disclosure()
    signing_algorithm = signer.algorithm

    body: dict[str, Any] = {
        "schema_version": "v1",
        "framework": framework,
        "framework_key": framework_key,
        "framework_label": framework_label,
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
        "scope": {
            "since": since_dt.isoformat(),
            "until": until_dt.isoformat(),
            "control_count": len(controls),
            # One finding maps to many controls. ``evidence_row_count`` counts
            # control-to-finding mapping rows; ``distinct_finding_count`` counts
            # the findings themselves and reconciles with /v1/findings.
            "evidence_row_count": evidence_row_count,
            "distinct_finding_count": len(distinct_finding_ids),
            "audit_event_count": len(audit_in_window),
            "audit_events_truncated": audit_truncated,
            "audit_event_limit": audit_fetch_limit,
            "completed_scan_count": completed_scan_count,
        },
        "summary": {
            "pass": pass_count,
            "warning": warn_count,
            "fail": fail_count,
            "incomplete": incomplete_count,
            "not_evaluated": not_evaluated_count,
            "applicable": status_counts["applicable"],
            "not_applicable": status_counts["not_applicable"],
            "score": bundle_verdict.score if bundle_scored else None,
            "status": bundle_verdict.status if bundle_scored else "not_scored",
            # The score is over EVALUATED controls; it never travels alone.
            "evaluated": bundle_verdict.evaluated,
        },
        "controls": enriched_controls,
        "audit_events": [entry.to_dict() for entry in audit_in_window],
        "audit_log_integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": len(audit_in_window),
            "truncated": audit_truncated,
        },
        "signature_algorithm": signing_algorithm,
        # Verifiability travels INSIDE the signed envelope (everything except
        # `signature` is canonicalised and signed), so a bundle from a
        # default deployment — per-process HMAC key, verifiable by nobody —
        # cannot be handed to an auditor with the disclosure quietly removed.
        "signature_disclosure": signer.as_bundle_field(),
        "threat_model": _bundle_threat_model(signing_algorithm, signer),
    }
    _attach_signer_key(body, signer)

    # Embed the signature IN the document. Shipping it only as a response header
    # meant `curl -o bundle.json` produced a file that advertised
    # signature_algorithm and carried nothing to verify. The signature covers the
    # canonical body with the `signature` field itself removed
    # (compliance_signing.canonical_bundle_payload) — the same canonical form for
    # both the json and jsonl renderings, so either saved artifact verifies
    # identically and byte-preserving the HTTP stream is no longer required.
    canonical = canonical_bundle_payload(body)
    bundle_signature = sign_compliance_bundle(canonical)
    body["signature"] = bundle_signature.signature_hex

    log_action(
        "compliance.report_exported",
        actor=actor,
        resource=f"compliance/{framework_key}",
        tenant_id=tenant_id,
        format=fmt,
        since=since_dt.isoformat(),
        until=until_dt.isoformat(),
        control_count=len(controls),
        evidence_row_count=evidence_row_count,
        distinct_finding_count=len(distinct_finding_ids),
        audit_event_count=len(audit_in_window),
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )

    filename = f"agent-bom-compliance-{framework_key.replace('_', '-')}.{'jsonl' if fmt == 'jsonl' else 'json'}"

    from agent_bom.api.metrics import record_compliance_export

    if fmt == "jsonl":
        payload = _jsonl_bundle_payload(body)
        record_compliance_export(signing_algorithm, framework_key, len(payload))
        return _ndjson_attachment(payload, filename, _bundle_signing_headers(bundle_signature))

    record_compliance_export(signing_algorithm, framework_key, len(json.dumps(body, sort_keys=True).encode()))
    return JSONResponse(
        content=body,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            **_bundle_signing_headers(bundle_signature),
        },
    )


# ─── Multi-framework evidence pack ─────────────────────────────────────────


@router.get("/compliance/report/pack", **documented(ComplianceEvidencePackResponse), tags=["compliance"])
def export_compliance_pack(
    request: Request,
    since: str | None = None,
    until: str | None = None,
) -> JSONResponse:
    """Export one signed evidence pack covering every tag-mapped framework.

    This is the auditor "grab everything" download: instead of pulling a
    per-framework bundle from ``/v1/compliance/{framework}/report`` one at a
    time, operators get a single tamper-evident JSON with each framework's
    controls, mapped findings, and the shared audit-window integrity totals.

    The pack shares the single-bundle security envelope: a fresh 128-bit
    ``nonce`` and explicit ``expires_at`` are inside the signed body, the
    signature (``X-Agent-Bom-Compliance-Report-Signature``) covers the
    canonical UTF-8 body, and every framework's evidence + the audit events
    are tenant-filtered so cross-tenant data never leaks into the pack.
    """
    now = datetime.now(timezone.utc)
    since_dt = _parse_iso_or_default(since, now - timedelta(days=30))
    until_dt = _parse_iso_or_default(until, now)
    if since_dt >= until_dt:
        raise HTTPException(status_code=400, detail="since must be earlier than until")

    raw_tenant_jobs = _tenant_jobs(request)
    full = _build_compliance(raw_tenant_jobs)
    from agent_bom.compliance_coverage import framework_report_labels_by_slug

    framework_map = framework_report_labels_by_slug()

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    from agent_bom.api.findings_current import current_scan_jobs

    tenant_jobs = list(
        current_scan_jobs(
            raw_tenant_jobs,
            since=None,
            scan_id=None,
            require_authoritative_evidence=True,
        )
    )
    blast_by_tag = _index_blast_radii_by_tag(tenant_jobs)
    completed_scan_count = sum(1 for job in tenant_jobs if job.status == JobStatus.DONE and bool(job.result))

    from agent_bom.api.audit_log import get_audit_log, log_action

    # Same honest-truncation contract as the single-framework report: a window
    # deeper than the cap is marked truncated, never presented as complete.
    audit_fetch_limit = _AUDIT_EVIDENCE_FETCH_LIMIT
    audit_in_window, audit_truncated, verified, tampered = _audit_window(
        get_audit_log(), since_dt, until_dt, tenant_id=tenant_id, fetch_limit=audit_fetch_limit
    )

    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    scored_by_slug = {metadata.slug: metadata.scored for metadata in TAG_MAPPED_FRAMEWORKS}

    rollup = _pack_framework_bundles(full, framework_map, scored_by_slug, blast_by_tag, completed_scan_count)
    framework_bundles = rollup["framework_bundles"]
    total_evidence_rows = rollup["total_evidence_rows"]
    all_finding_ids = rollup["all_finding_ids"]
    total_controls = rollup["total_controls"]
    combined_summary = rollup["combined_summary"]
    combined_detective_passes = rollup["combined_detective_passes"]

    nonce = secrets.token_hex(16)
    bundle_ttl_seconds = int(os.environ.get("AGENT_BOM_COMPLIANCE_BUNDLE_TTL_SECONDS", "86400"))
    bundle_ttl_seconds = max(60, min(bundle_ttl_seconds, 30 * 86400))
    expires_at = now + timedelta(seconds=bundle_ttl_seconds)

    from agent_bom.api.compliance_signing import (
        canonical_bundle_payload,
        describe_signer_disclosure,
        sign_compliance_bundle,
    )

    signer = describe_signer_disclosure()
    signing_algorithm = signer.algorithm

    body: dict[str, Any] = {
        "schema_version": "v1",
        "document_type": "compliance-evidence-pack",
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
        "scope": {
            "since": since_dt.isoformat(),
            "until": until_dt.isoformat(),
            "framework_count": len(framework_bundles),
            # Scored controls only — an applicability overlay has no controls to
            # count toward a control total.
            "control_count": total_controls,
            # A single finding maps to many controls across many frameworks, so
            # summing per-framework counts yields MAPPING ROWS, not findings.
            # Reporting rows as `finding_count` made a 25-finding tenant read as
            # 1342 findings in a document handed to an auditor.
            # `distinct_finding_count` reconciles with the findings spine.
            "evidence_row_count": total_evidence_rows,
            "distinct_finding_count": len(all_finding_ids),
            "audit_event_count": len(audit_in_window),
            "audit_events_truncated": audit_truncated,
            "audit_event_limit": audit_fetch_limit,
            "completed_scan_count": completed_scan_count,
        },
        "summary": {
            **combined_summary,
            # Same scorer as every other surface. Scoring pass/total_controls
            # here let the pack disagree with the aggregate: once detective
            # passes were preserved (rather than downgraded to `incomplete`),
            # this reported 3.3% over an estate the aggregate calls no_data.
            "score": score_compliance(
                passed=combined_summary["pass"],
                warned=combined_summary["warning"],
                failed=combined_summary["fail"],
                detective_passes=min(combined_detective_passes, combined_summary["pass"]),
                has_evidence=completed_scan_count > 0,
            ).score,
        },
        "frameworks": framework_bundles,
        "audit_events": [entry.to_dict() for entry in audit_in_window],
        "audit_log_integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": len(audit_in_window),
            "truncated": audit_truncated,
        },
        "signature_algorithm": signing_algorithm,
        # Same in-envelope disclosure contract as the single-framework bundle.
        "signature_disclosure": signer.as_bundle_field(),
    }
    _attach_signer_key(body, signer)

    # Same embedded-signature contract as the single-framework bundle: the pack
    # carries its own signature so a saved file is verifiable off-line.
    sig_result = sign_compliance_bundle(canonical_bundle_payload(body))
    body["signature"] = sig_result.signature_hex

    log_action(
        "compliance.pack_exported",
        actor=actor,
        resource="compliance/pack",
        tenant_id=tenant_id,
        since=since_dt.isoformat(),
        until=until_dt.isoformat(),
        framework_count=len(framework_bundles),
        control_count=total_controls,
        evidence_row_count=total_evidence_rows,
        distinct_finding_count=len(all_finding_ids),
        audit_event_count=len(audit_in_window),
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )

    from agent_bom.api.metrics import record_compliance_export

    record_compliance_export(signing_algorithm, "pack", len(json.dumps(body, sort_keys=True).encode()))
    headers = {"Content-Disposition": 'attachment; filename="agent-bom-compliance-pack.json"', **_bundle_signing_headers(sig_result)}
    return JSONResponse(content=body, headers=headers)


router.include_router(reads.posture_router)


@router.get("/posture/counts", **read_models.documented(read_models.PostureCountsResponse), tags=["compliance"])
async def get_posture_counts(request: Request) -> dict:
    """Aggregate open-finding severity counts across all completed scans.

    Lightweight endpoint used by the dashboard nav to show Critical/High
    badges. Reads the SAME reconciled source of truth as the ``/v1/overview``
    exec headline — the unified findings spine folded with hub-ingested
    evidence (#3961) — so the nav badges can never disagree with the overview's
    critical/high. The CVE-only ``blast_radius`` is used only for the
    correlation-based ``compound_issues`` metric, where reachability/exposure
    lives. ``unrated`` is an explicit bucket so the histogram sums to ``total``.

    Returns:
        {critical, high, medium, low, unrated, total, kev, compound_issues, …}
    """
    try:
        async with adaptive_backpressure("overview"):
            return await anyio.to_thread.run_sync(_get_posture_counts_impl, request)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


router.include_router(reads.posture_detail_router)


# ─── Compliance Hub (#1044 PR C) ──────────────────────────────────────────────


_HUB_VALID_FORMATS = ("sarif", "cyclonedx", "csv", "json")


@router.post(
    "/compliance/ingest",
    tags=["compliance"],
    status_code=201,
    dependencies=[_dep("scan")],
)
async def ingest_compliance_findings(request: Request) -> dict:
    """Ingest external findings (SARIF / CycloneDX / CSV / JSON).

    Body:
        {"format": "sarif" | "cyclonedx" | "csv" | "json",
         "content": "<file body as a string>"}

    The content is parsed via the matching adapter in
    ``compliance_hub_ingest``; every produced finding is hub-classified
    and appended to the tenant's hub store. Returns the per-framework
    framework-hit breakdown so the caller can verify classification ran.
    """
    import tempfile
    from pathlib import Path

    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.compliance_coverage import normalize_framework_slug
    from agent_bom.compliance_hub_ingest import ingest_findings

    body = await read_compliance_ingest_body(request)
    fmt = (body.get("format") or "").lower()
    if fmt not in _HUB_VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"format must be one of {list(_HUB_VALID_FORMATS)}",
        )
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="content (string) is required")

    suffix = ".csv" if fmt == "csv" else ".json"
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        findings = ingest_findings(tmp_path, fmt=fmt)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    if not findings:
        raise HTTPException(
            status_code=422,
            detail=f"No findings parsed from {fmt} content. Check the format matches the body shape (e.g. SARIF runs[].results[]).",
        )

    payloads = [f.to_dict() for f in findings]
    for payload in payloads:
        # Preserve the parser's semantic finding source (for example
        # ``EXTERNAL``) separately from the durable import stream used to scope
        # absent reconciliation.  Conflating the two made a CSV/SARIF
        # reconcile report success while resolving zero prior findings.
        payload["ingest_source"] = fmt
        payload["origin"] = "bulk_ingest"
        frameworks = payload.get("applicable_frameworks")
        if isinstance(frameworks, list):
            payload["applicable_frameworks"] = [normalize_framework_slug(str(slug)) for slug in frameworks if slug]
    tenant_id = _tenant_id(request)
    store = get_compliance_hub_store()
    from agent_bom.api.finding_lifecycle import normalize_observed_at

    observed_at = normalize_observed_at(body.get("observed_at"))
    # Deterministic batch id keyed on the Idempotency-Key header (if any) or the
    # request-content fingerprint, so re-POSTing the same document collapses onto
    # one observation batch instead of inflating ``scan_count`` on every resend
    # (P1-5). The (canonical, batch_id) observation key must be stable per body.
    from agent_bom.api.idempotency_store import deterministic_batch_id, idempotency_request_fingerprint

    idem_key = request.headers.get("Idempotency-Key") or ""
    batch_id = deterministic_batch_id(idem_key or idempotency_request_fingerprint(body))

    # Offload the blocking psycopg write sequence (ledger append + current-state
    # upsert + reconcile + delta emission) to a worker thread so concurrent
    # compliance ingest cannot freeze the event loop and unrelated requests
    # (mirrors the bulk ingest and read paths). See ``hub_ingest_store_writes`` /
    # ``hub_store_call``.
    from agent_bom.api.hub_ingest import hub_ingest_store_writes, hub_store_call
    from agent_bom.api.hub_observations_partition import (
        ObservationPartitionRangeError,
        ObservationPartitionUnavailableError,
    )

    try:
        store_result = await hub_store_call(
            hub_ingest_store_writes,
            store,
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=fmt,
            reconcile_absent=bool(body.get("reconcile_absent")),
        )
    except ObservationPartitionRangeError as exc:
        # observed_at is so far past/future it is almost certainly bad data — a
        # clean 422 instead of a raw partition CheckViolation 500 (mirrors the
        # bulk ingest route).
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    except ObservationPartitionUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail="Observation storage is not provisioned for this timestamp; run database migrations.",
        ) from exc
    new_total = store_result["new_total"]
    reconciled = store_result["reconciled"]
    delta_results = store_result["delta_results"]

    framework_counts: dict[str, int] = {}
    for payload in payloads:
        for slug in payload.get("applicable_frameworks") or []:
            framework_counts[slug] = framework_counts.get(slug, 0) + 1

    response = {
        "ingested": len(payloads),
        "distinct_findings": store_result["distinct_findings"],
        "duplicate_payloads": store_result["duplicate_payloads"],
        "tenant_total": new_total,
        "format": fmt,
        "observed_at": observed_at,
        "framework_hits": dict(sorted(framework_counts.items())),
    }
    if body.get("reconcile_absent"):
        response["reconciled"] = reconciled
    if delta_results:
        delivered = sum(
            1
            for result in delta_results
            if (result.get("status") == "delivered" if isinstance(result, dict) else getattr(result, "delivered", False))
        )
        response["delta_stream"] = {"emitted_batches": len(delta_results), "delivered": delivered}
    return response


router.include_router(reads.hub_router)


@router.get("/compliance/hub/posture", **read_models.documented(read_models.HubPostureResponse), tags=["compliance"])
async def get_hub_posture(request: Request) -> dict:
    """Aggregate compliance posture across native scans + hub-ingested findings.

    Returns per-framework counts, severity breakdown, and source mix
    (native vs external) so the dashboard /compliance page can render a
    single posture story across every entry point.

    The synchronous store aggregates (severity GROUP BY, SQL-side framework
    counts, tenant total) plus the native-job fold run in a worker thread under
    adaptive backpressure so this O(table) read cannot block the event loop and
    starve ``/health`` (mirrors ``/v1/findings``); under saturation it sheds with
    ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_get_hub_posture_impl, request)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


@router.delete("/compliance/hub/findings", tags=["compliance"], dependencies=[_dep("policy_write")])
async def clear_hub_findings(request: Request) -> dict:
    """Clear all hub-ingested findings for the current tenant.

    Useful when a tenant wants to re-import a clean batch (e.g. after
    a scanner-version upgrade). Native scan results are not affected.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    removed = await anyio.to_thread.run_sync(get_compliance_hub_store().clear, _tenant_id(request))
    return {"removed": removed}
