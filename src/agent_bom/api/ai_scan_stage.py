"""The scan pipeline's advisory AI step. Whatever happens here, the scanner's results stand."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.ai_components.ai_policy import control_plane_decision, control_plane_model
from agent_bom.ai_components.call_audit import ai_call_scope
from agent_bom.ai_enrich import run_ai_enrichment_sync
from agent_bom.api.ai_assessment_read import persist_scan_assessments
from agent_bom.api.ai_call_sink import ensure_ai_call_sink
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)


def run_advisory_ai(ctx: Any, report: Any) -> None:
    req = ctx.req
    tenant_id = ctx.job.tenant_id or "default"
    scan_id = ctx.job.job_id
    decision = control_plane_decision(tenant_id)
    if not decision.enabled:
        report.ai_enrichment_metadata = {"status": "disabled", "reason": decision.reason, "advisory_default": True}
        persist_scan_assessments(tenant_id, scan_id, report)
        ctx.progress("Advisory AI is off for this deployment")
        return
    failed = False
    try:
        ensure_ai_call_sink()
        with ai_call_scope(tenant_id=tenant_id, actor=str(ctx.job.triggered_by or "scan"), audit_required=True):
            run_ai_enrichment_sync(report, model=control_plane_model(req.ai_model), deterministic=req.ai_deterministic)
    except Exception as ai_exc:  # noqa: BLE001
        failed = True
        _logger.warning("Advisory AI enrichment skipped: %s", sanitize_text(sanitize_error(ai_exc, generic=True)))
        ctx.progress("Advisory AI enrichment skipped")
    persist_scan_assessments(tenant_id, scan_id, report, failed=failed)
