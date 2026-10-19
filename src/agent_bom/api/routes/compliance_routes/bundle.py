"""Signed evidence bundle helpers shared by the report and evidence-pack routes."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, cast

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from agent_bom.api.models import JobStatus
from agent_bom.api.routes.compliance_routes.evidence import _result_compliance_evidence
from agent_bom.core.timestamps import parse_timestamp
from agent_bom.evidence.control_modes import MODE_DETECTIVE
from agent_bom.evidence.scoring import score_compliance


def _parse_iso_or_default(value: str | None, default: datetime) -> datetime:
    """Use the default for missing input; reject invalid timestamps with HTTP 400."""
    if not value:
        return default
    parsed = parse_timestamp(value)
    if parsed is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid timestamp '{value}'. Use ISO-8601 with timezone.",
        )
    return parsed


def _evidence_for_control(
    control: dict,
    blast_radii_by_tag: dict[str, list[dict]],
) -> list[dict]:
    """Map a control's tags onto the matching blast-radius findings."""
    seen_finding_ids: set[str] = set()
    evidence: list[dict] = []
    tags = list(control.get("tags", []) or [])
    fallback_tag = control.get("control_id") or control.get("code") or control.get("id")
    if fallback_tag and fallback_tag not in tags:
        tags.append(str(fallback_tag))
    for tag in tags:
        for br in blast_radii_by_tag.get(tag, []):
            finding_id = br.get("finding_id") or f"{br.get('vulnerability_id', '')}@{br.get('package', '')}"
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)
            evidence.append(
                {
                    "finding_id": finding_id,
                    "control_tag": tag,
                    "vulnerability_id": br.get("vulnerability_id"),
                    "package": br.get("package"),
                    "severity": br.get("severity"),
                    "scan_id": br.get("scan_id"),
                    "scan_input": br.get("scan_input") or {},
                    "scanner_version": br.get("scanner_version"),
                    "scan_started_at": br.get("scan_started_at"),
                    "scan_completed_at": br.get("scan_completed_at"),
                    "policy_decisions": br.get("policy_decisions") or [],
                    "provenance": br.get("provenance") or {},
                    "fixed_version": br.get("fixed_version"),
                    "agents_at_risk": br.get("affected_agents") or [],
                }
            )
    return evidence


def _scan_request_payload(job: Any) -> dict:
    request = getattr(job, "request", None)
    if request is None:
        return {}
    if hasattr(request, "model_dump"):
        return cast(dict, request.model_dump(exclude_none=True))
    if hasattr(request, "dict"):
        return cast(dict, request.dict(exclude_none=True))
    if isinstance(request, dict):
        return {k: v for k, v in request.items() if v is not None}
    return {}


def _index_blast_radii_by_tag(jobs: list) -> dict[str, list[dict]]:
    """Build a flat tag → canonical-finding index across completed scans."""
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS

    by_tag: dict[str, list[dict]] = {}
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_id = job.result.get("scan_id") or job.job_id
        scan_context = {
            "scan_id": scan_id,
            "scan_input": _scan_request_payload(job),
            "scanner_version": job.result.get("scanner_version") or job.result.get("agent_bom_version"),
            "scan_started_at": getattr(job, "created_at", None),
            "scan_completed_at": getattr(job, "completed_at", None),
            "policy_decisions": job.result.get("policy_decisions") or [],
            "provenance": job.result.get("provenance") or job.result.get("scan_provenance") or {},
        }
        for br in _result_compliance_evidence(job.result):
            br_with_scan = {**br, **scan_context}
            for tag_field in COMPLIANCE_TAG_FIELDS:
                for tag in br.get(tag_field, []) or []:
                    by_tag.setdefault(tag, []).append(br_with_scan)
    return by_tag


def _bundle_control_status(
    source_status: str,
    evidence: list[dict],
    *,
    has_completed_scans: bool,
    evaluation_mode: str | None = None,
) -> tuple[str, str]:
    """Map an API control status onto its bundle status + evidence state.

    The bundle is the auditor's copy of what the API reports, so it must not
    invent a different verdict. Two statuses previously had no mapping and fell
    through to ``not_evaluated``/``incomplete``, making the signed artifact
    contradict the live API:

    * A **detective** control (RA-5, CM-8, CIS-07.1 …) passes because a
      completed, in-window scan IS the control operating. The taggers
      deliberately never map findings onto it, so demanding finding evidence
      downgraded every detective pass to ``incomplete`` — a bar it could not
      ever clear. Its evidence is the scan, recorded as ``scan_evidence``.
    * **Applicability-overlay** statuses (MITRE ATT&CK ``applicable`` /
      ``not_applicable``) are not pass/fail claims at all and pass through
      unchanged, so the overlay's counters stop reading 0.
    """
    status = (source_status or "unknown").lower()
    if not has_completed_scans:
        return "not_evaluated", "missing_scan"
    if status in {"applicable", "not_applicable"}:
        return status, "complete" if evidence else status
    if status == "pass" and evaluation_mode == MODE_DETECTIVE:
        return "pass", "scan_evidence"
    if status in {"pass", "warning", "fail"} and not evidence:
        return "incomplete", "missing_control_evidence"
    if evidence:
        return status, "complete"
    if status in {"not_evaluated", "incomplete", "not_assessed"}:
        return status, status
    return "not_evaluated", "missing_control_evidence"


def _detective_pass_count(controls: list[dict], ceiling: int | None = None) -> int:
    """How many of ``controls`` pass ONLY because a scan ran.

    ``score_compliance`` subtracts these to decide whether anything substantive
    was measured. ``ceiling`` clamps the result to the caller's own pass count,
    which can be lower when a control's bundle status differs from its API
    status (an overlay entry, or a pass without finding evidence).
    """
    count = sum(1 for c in controls if c.get("evaluation_mode") == MODE_DETECTIVE and str(c.get("status", "")).lower() == "pass")
    return min(count, ceiling) if ceiling is not None else count


def _verify_audit_entries(entries: list) -> tuple[int, int]:
    """Verify only the entries included in the exported bundle."""
    verified = 0
    tampered = 0
    for entry in entries:
        if entry.verify():
            verified += 1
        else:
            tampered += 1
    return verified, tampered


def _enrich_controls_with_evidence(
    controls: list[dict],
    blast_by_tag: dict[str, list[dict]],
    *,
    completed_scan_count: int,
) -> tuple[list[dict], int, set[str], dict[str, int]]:
    """Pair each control with its blast-radius evidence and roll up bundle-status counts.

    Shared by the single-framework report bundle and the multi-framework
    evidence pack so both surfaces map controls to findings identically.

    Returns ``(controls, evidence_row_count, distinct_finding_ids, status_counts)``.
    A finding maps to many controls, so the row count is always >= the number of
    distinct findings. Reporting rows as a "finding count" made a 25-finding
    tenant read as 1342 findings in a document handed to an auditor; the two are
    now counted and named separately.
    """
    enriched_controls: list[dict] = []
    evidence_row_count = 0
    distinct_finding_ids: set[str] = set()
    for control in controls:
        evidence = _evidence_for_control(control, blast_by_tag)
        evidence_row_count += len(evidence)
        distinct_finding_ids.update(str(row.get("finding_id")) for row in evidence if row.get("finding_id"))
        source_status = str(control.get("status", "unknown")).lower()
        bundle_status, evidence_state = _bundle_control_status(
            source_status,
            evidence,
            has_completed_scans=completed_scan_count > 0,
            evaluation_mode=control.get("evaluation_mode"),
        )
        enriched_controls.append(
            {
                "control_id": control.get("control_id") or control.get("id"),
                "control_name": control.get("name") or control.get("title"),
                "status": bundle_status,
                "source_status": source_status,
                "evidence_state": evidence_state,
                "finding_count": len(evidence),
                "evidence": evidence,
            }
        )
    counts = {
        "pass": sum(1 for c in enriched_controls if c.get("status") == "pass"),
        "warning": sum(1 for c in enriched_controls if c.get("status") == "warning"),
        "fail": sum(1 for c in enriched_controls if c.get("status") == "fail"),
        "incomplete": sum(1 for c in enriched_controls if c.get("status") == "incomplete"),
        "not_evaluated": sum(1 for c in enriched_controls if c.get("status") == "not_evaluated"),
        # Applicability-overlay entries (MITRE ATT&CK) are not controls the
        # estate passed or failed; they are counted, never scored.
        "applicable": sum(1 for c in enriched_controls if c.get("status") == "applicable"),
        "not_applicable": sum(1 for c in enriched_controls if c.get("status") == "not_applicable"),
    }
    return enriched_controls, evidence_row_count, distinct_finding_ids, counts


def _audit_window(store: Any, since_dt: datetime, until_dt: datetime, *, tenant_id: str, fetch_limit: int) -> tuple[list, bool, int, int]:
    """Tenant audit entries inside ``[since, until]`` plus their integrity totals.

    ``list_entries`` returns most-recent-first, so hitting ``fetch_limit``
    drops the OLDEST in-window entries — callers mark the bundle truncated
    rather than present a partial window as complete.
    """
    audit_since_iso = since_dt.isoformat()
    audit_entries = store.list_entries(since=audit_since_iso, limit=fetch_limit, tenant_id=tenant_id)
    audit_truncated = len(audit_entries) >= fetch_limit
    until_iso = until_dt.isoformat()
    audit_in_window = [e for e in audit_entries if audit_since_iso <= (e.timestamp or "") <= until_iso]
    verified, tampered = _verify_audit_entries(audit_in_window)
    return audit_in_window, audit_truncated, verified, tampered


def _bundle_threat_model(signing_algorithm: str, signer: Any) -> dict[str, str]:
    return {
        "integrity": (
            f"{signing_algorithm} over the canonical UTF-8 body. Tampering with any field invalidates the signature."
            if signer.signature_verifiable
            else f"{signing_algorithm} over the canonical UTF-8 body, but with a signing key no verifier can hold — "
            "see signature_disclosure. Treat this bundle as unsigned evidence until the deployment is reconfigured "
            "and the bundle re-exported."
        ),
        "confidentiality": (
            "The bundle is cleartext at the application layer by design — auditors "
            "need to read it. Operators MUST serve /v1/compliance/* over TLS so the "
            "bundle is not sniffable in transit."
        ),
        "replay": (
            "nonce + expires_at are inside the signed envelope. A re-issued bundle "
            "past expires_at is expected to be rejected by the consumer."
        ),
        "non_repudiation": (
            "Ed25519 provides asymmetric non-repudiation — verifiers only need the "
            "public key (at /v1/compliance/verification-key). HMAC is a shared secret "
            "so it does NOT provide true non-repudiation; for forensic cases cross-"
            "reference the compliance.report_exported audit entry."
            if signing_algorithm == "Ed25519"
            else "HMAC is a shared secret between server and auditor; it does NOT provide "
            "true non-repudiation. For forensic cases requiring non-repudiation, "
            "cross-reference the compliance.report_exported audit entry, or configure "
            "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM to switch to Ed25519 signing."
        ),
    }


def _attach_signer_key(body: dict[str, Any], signer: Any) -> None:
    if signer.key_id is not None:
        body["signature_key_id"] = signer.key_id
    if signer.public_key_pem is not None:
        body["signature_public_key_pem"] = signer.public_key_pem


def _bundle_signing_headers(bundle_signature: Any) -> dict[str, str]:
    """Mirror the embedded signature into headers for streaming consumers."""
    headers = {
        "X-Agent-Bom-Compliance-Report-Signature": bundle_signature.signature_hex,
        "X-Agent-Bom-Compliance-Signature-Algorithm": bundle_signature.algorithm,
    }
    if bundle_signature.key_id is not None:
        headers["X-Agent-Bom-Compliance-Signature-KeyId"] = bundle_signature.key_id
    return headers


def _jsonl_bundle_payload(body: dict[str, Any]) -> bytes:
    # jsonl streams one control per line so SIEM and security-lake
    # consumers can ingest without loading the whole bundle. The meta line
    # carries the same embedded `signature` as the json rendering, and it
    # covers the same canonical JSON body — a consumer reassembles
    # meta + controls + audit_events and verifies without depending on the
    # stream's byte layout.
    lines = [json.dumps({"meta": {k: v for k, v in body.items() if k not in {"controls", "audit_events"}}}, sort_keys=True)]
    for control in body["controls"]:
        lines.append(json.dumps({"control": control}, sort_keys=True))
    for entry in body["audit_events"]:
        lines.append(json.dumps({"audit": entry}, sort_keys=True))
    return ("\n".join(lines) + "\n").encode()


def _ndjson_attachment(payload: bytes, filename: str, signing_headers: dict[str, str]) -> StreamingResponse:
    async def _iter_chunks(data: bytes, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]:
        for offset in range(0, len(data), chunk_size):
            yield data[offset : offset + chunk_size]

    return StreamingResponse(
        _iter_chunks(payload),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(payload)),
            **signing_headers,
        },
    )


def _pack_framework_bundles(
    full: dict[str, Any],
    framework_map: dict[str, tuple[str, str]],
    scored_by_slug: dict[str, bool],
    blast_by_tag: dict[str, list[dict]],
    completed_scan_count: int,
) -> dict[str, Any]:
    """Per-framework evidence bundles plus the pack-wide rollups."""
    framework_bundles: list[dict[str, Any]] = []
    total_evidence_rows = 0
    all_finding_ids: set[str] = set()
    total_controls = 0
    combined_summary = {
        "pass": 0,
        "warning": 0,
        "fail": 0,
        "incomplete": 0,
        "not_evaluated": 0,
        "applicable": 0,
        "not_applicable": 0,
    }
    combined_detective_passes = 0
    for slug, (framework_key, framework_label) in framework_map.items():
        controls = full.get(framework_key, [])
        scored = scored_by_slug.get(slug, True)
        enriched_controls, framework_rows, framework_finding_ids, status_counts = _enrich_controls_with_evidence(
            controls,
            blast_by_tag,
            completed_scan_count=completed_scan_count,
        )
        total_evidence_rows += framework_rows
        all_finding_ids |= framework_finding_ids
        if scored:
            total_controls += len(controls)
        for key in combined_summary:
            combined_summary[key] += status_counts[key]
        if scored:
            combined_detective_passes += _detective_pass_count(controls, status_counts["pass"])
        framework_bundles.append(
            _pack_framework_entry(slug, framework_key, framework_label, scored, controls, status_counts, completed_scan_count)
        )
        framework_bundles[-1].update(
            {
                "control_count": len(controls),
                "evidence_row_count": framework_rows,
                "distinct_finding_count": len(framework_finding_ids),
                "controls": enriched_controls,
            }
        )
    return {
        "framework_bundles": framework_bundles,
        "total_evidence_rows": total_evidence_rows,
        "all_finding_ids": all_finding_ids,
        "total_controls": total_controls,
        "combined_summary": combined_summary,
        "combined_detective_passes": combined_detective_passes,
    }


def _pack_framework_entry(
    slug: str,
    framework_key: str,
    framework_label: str,
    scored: bool,
    controls: list[dict],
    status_counts: dict[str, int],
    completed_scan_count: int,
) -> dict[str, Any]:
    return {
        "framework": slug,
        "framework_key": framework_key,
        "framework_label": framework_label,
        # An applicability overlay has no pass rate to report — a score
        # would read as "0% of ATT&CK passing" for something that cannot
        # pass. Null says so; the applicable counts carry the signal.
        "scored": scored,
        "summary": {
            **status_counts,
            "score": (
                score_compliance(
                    passed=status_counts["pass"],
                    warned=status_counts["warning"],
                    failed=status_counts["fail"],
                    detective_passes=_detective_pass_count(controls, status_counts["pass"]),
                    has_evidence=completed_scan_count > 0,
                ).score
                if scored
                else None
            ),
        },
    }
