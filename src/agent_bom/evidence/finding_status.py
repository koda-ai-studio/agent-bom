"""Public lifecycle and suppression receipts without exception free text."""

from collections.abc import Mapping
from typing import Any

from agent_bom.evidence.finding_stale import is_stale

RESOLUTION_REASONS = frozenset({"no_longer_detected", "asset_deleted"})
_STATUSES = frozenset({"open", "reopened", "resolved", "suppressed", "accepted", "not_affected", "fixed"})


def public_finding_status(row: Mapping[str, Any]) -> dict[str, Any]:
    from agent_bom.security import sanitize_text

    payload: dict[str, Any] = {}
    lifecycle = str(row.get("lifecycle_status") or row.get("status") or "").strip().lower()
    if lifecycle in _STATUSES:
        payload.update(status=lifecycle, lifecycle_status=lifecycle)
    reason = row.get("resolution_reason")
    payload["resolution_reason"] = reason if lifecycle == "resolved" and reason in RESOLUTION_REASONS else None
    # A grouped issue already folded this across its occurrences.
    payload["stale"] = row.get("stale") is True if "open_occurrence_count" in row else is_stale(row)
    suppressed = row.get("suppressed")
    if isinstance(suppressed, bool):
        payload["suppressed"] = suppressed
        receipt = row.get("suppression_id")
        payload["suppression_id"] = (
            sanitize_text(receipt.strip(), max_len=128) if suppressed and isinstance(receipt, str) and receipt.strip() else None
        )
        if suppressed and lifecycle in {"", "open", "reopened", "suppressed"}:
            payload["status"] = "suppressed"
    if isinstance(row.get("actionable"), bool):
        payload["actionable"] = row["actionable"]
    return payload
