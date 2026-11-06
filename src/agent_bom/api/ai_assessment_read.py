"""Join stored AI advice onto finding rows and record a scan's advice. Never calls a model."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from agent_bom.ai_components.call_audit import best_effort
from agent_bom.ai_components.triage_guard import guard_verdict
from agent_bom.api.ai_assessment_store import get_ai_assessment_store

_T = TypeVar("_T")
_UNAVAILABLE_WARNING = "AI advice is unavailable for this page; scanner findings are unaffected."
_ROW_ID_KEYS = ("id", "finding_id", "canonical_id")


def _optional_advice(operation: Callable[[], _T]) -> _T | None:
    return best_effort(operation, "AI advice store call")


def _row_ids(row: dict[str, Any]) -> list[str]:
    return [str(row[key]) for key in _ROW_ID_KEYS if row.get(key)]


def _mark_group_scope(advice: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """A grouped row shows one occurrence's advice, and has to say so."""
    count = row.get("occurrence_count")
    if isinstance(count, int) and count > 1:
        return {**advice, "advice_covers_occurrences": 1, "group_occurrences": count}
    return advice


def attach_ai_assessments(body: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Add ``ai_assessment`` to the rows of a findings page; a store failure costs only the advice."""
    rows = body.get("findings")
    if not isinstance(rows, list) or not rows:
        return body
    wanted = [identifier for row in rows if isinstance(row, dict) for identifier in _row_ids(row)]
    stored = _optional_advice(lambda: get_ai_assessment_store().latest_for_findings(tenant_id, wanted))
    if stored is None:
        warnings = body.get("warnings")
        if isinstance(warnings, list):
            warnings.append(_UNAVAILABLE_WARNING)
        return body
    if not stored:
        return body
    for row in rows:
        if not isinstance(row, dict):
            continue
        match = next((stored[identifier] for identifier in _row_ids(row) if identifier in stored), None)
        if match is not None:
            row["ai_assessment"] = _mark_group_scope(guard_verdict(match, row), row)
    return body


def run_status(metadata: dict[str, Any], assessed: int, *, failed: bool = False) -> str:
    """One word for how a scan's AI step went."""
    if failed:
        return "failed"
    if metadata.get("status") == "failed" and assessed:
        return "partial"
    if metadata.get("status") in {"disabled", "blocked", "unavailable", "failed"}:
        return str(metadata["status"])
    scope = metadata.get("triage_scope")
    offered = int(scope.get("findings_offered") or 0) if isinstance(scope, dict) else 0
    if not offered:
        return "ok"
    if assessed == 0:
        return "failed"
    return "ok" if assessed >= offered else "partial"


def persist_scan_assessments(tenant_id: str, scan_id: str, report: Any, *, failed: bool = False) -> None:
    """Store what this scan's AI step produced, or the fact that it produced nothing."""
    metadata = dict(getattr(report, "ai_enrichment_metadata", None) or {})
    assessments = [item.model_dump(mode="json") for item in getattr(report, "ai_finding_assessments", []) or []]
    scope = metadata.get("triage_scope")
    run = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": run_status(metadata, len(assessments), failed=failed),
        "reason": str(metadata.get("reason") or ""),
        "provider": metadata.get("provider"),
        "model": metadata.get("model"),
        "local": bool(metadata.get("local")),
        "prompt_version": metadata.get("triage_prompt_version"),
        "dataset_version": metadata.get("triage_dataset_version"),
        "triage_scope": scope if isinstance(scope, dict) else {},
        "call_budget": metadata.get("call_budget"),
    }
    _optional_advice(lambda: get_ai_assessment_store().put_scan(tenant_id, scan_id, run, assessments))


def ai_status(tenant_id: str, *, enabled: bool, reason: str, model: str) -> dict[str, Any]:
    last_run = _optional_advice(lambda: get_ai_assessment_store().latest_run(tenant_id))
    state = "on" if enabled else "off"
    if enabled and last_run and last_run.get("status") in {"failed", "unavailable", "blocked"}:
        state = "degraded"
    return {
        "schema_version": "ai.status.v1",
        "state": state,
        "reason": reason,
        "advisory_only": True,
        "model": model or None,
        "last_run": last_run,
    }
