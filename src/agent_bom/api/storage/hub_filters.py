"""Compliance hub filters implementation."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from agent_bom.api.finding_cursor import (
    cursor_from_current_row,
    cvss_sort_value,
    finding_order_clause,
)
from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score
from agent_bom.api.storage.hub_contract import (
    _LEDGER_ORDINAL_SENTINEL,
    _LIST_PAGE_SORTS,
    _LIVE_STATUSES,
    _REACH_SORT_KEY,
    _SCOPE_FILTER_DEADLINE_SECONDS,
    _SCOPE_FILTER_MAX_BATCH,
    _SCOPE_FILTER_MIN_BATCH,
    _SCOPE_FILTER_SCAN_BUDGET,
    STATUS_FILTERS,
    _CurrentPageSortKey,
)
from agent_bom.core.settings import env_raw
from agent_bom.core.severity import severity_policy_rank
from agent_bom.evidence.finding_reach_sources import SERVER_STAMPED_REACH_FIELDS, without_fields


def scope_filter_batch_size(page_limit: int) -> int:
    """Bounded batch size for the scope-filtered keyset scan (never the table)."""
    return min(_SCOPE_FILTER_MAX_BATCH, max(_SCOPE_FILTER_MIN_BATCH, int(page_limit) + 1))


def scope_filter_scan_budget() -> int:
    """Rows one scope-filtered page walk may examine before it stops.

    Operator-tunable so a deployment with a very sparse scope filter can trade
    latency for completeness. Resolved per call (not bound at import) so the
    knob applies without a restart and stays testable.
    """
    raw = env_raw("AGENT_BOM_SCOPE_FILTER_SCAN_BUDGET")
    if raw is None:
        return _SCOPE_FILTER_SCAN_BUDGET
    try:
        return max(1, int(raw))
    except ValueError:
        return _SCOPE_FILTER_SCAN_BUDGET


def scope_filter_deadline_seconds() -> float:
    """Wall-clock ceiling for one scope-filtered page walk."""
    raw = env_raw("AGENT_BOM_SCOPE_FILTER_DEADLINE_SECONDS")
    if raw is None:
        return _SCOPE_FILTER_DEADLINE_SECONDS
    try:
        return max(0.001, float(raw))
    except ValueError:
        return _SCOPE_FILTER_DEADLINE_SECONDS


def normalize_status_filter(status: str | None) -> str | None:
    """Canonicalize a lifecycle-status filter.

    ``None`` -> ``None`` (no predicate; legacy all-history behavior). ``open`` /
    ``resolved`` / ``all`` pass through. An unrecognized value collapses to
    ``None`` (never silently HIDES rows — the route validates + 422s the user).
    """
    if status is None:
        return None
    key = status.strip().lower()
    return key if key in STATUS_FILTERS else None


def status_sql_predicate(status: str | None, placeholder: str = "?") -> tuple[str, list[Any]]:
    """SQL fragment + params for the lifecycle-status filter over ``status``.

    ``open`` (live posture) -> ``status IN (open, reopened)``; ``resolved`` ->
    ``status = resolved``; ``None`` / ``all`` -> no predicate. Rides the
    ``status`` column (and the open partial index for the default sort/COUNT), so
    it stays sargable — no filesort.
    """
    normalized = normalize_status_filter(status)
    if normalized == "open":
        return f"status IN ({placeholder}, {placeholder})", ["open", "reopened"]
    if normalized == "resolved":
        return f"status = {placeholder}", ["resolved"]
    return "", []


def status_matches(row: Mapping[str, Any], status: str | None) -> bool:
    """In-memory mirror of :func:`status_sql_predicate`.

    A row with no explicit lifecycle status is treated as ``open`` — scan
    findings (no reconcile lifecycle) are live by construction, so the default
    and ``all`` include them and ``resolved`` excludes them.
    """
    normalized = normalize_status_filter(status)
    if normalized is None or normalized == "all":
        return True
    payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
    row_status = str(row.get("status") or (payload or {}).get("status") or "open").strip().lower() or "open"
    if normalized == "open":
        return row_status in _LIVE_STATUSES and row.get("suppressed") is not True  # suppressed: evidence, not live
    return row_status == "resolved"


def collect_scope_filtered_page(
    fetch_batch: Callable[[str | None, int], tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]],
    *,
    predicate: Callable[[dict[str, Any]], bool],
    page_limit: int,
    start_cursor: str | None,
    sort: str,
    batch_size: int,
    scan_budget: int | None = None,
    deadline_monotonic: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Collect a bounded page from ``(current_row, enriched_payload)`` batches.

    Apply ``predicate`` until page_limit + 1 matches, exhaustion, or the
    row/time budget. Accumulate scanned_rows, scan_budget, truncated and reason
    in metadata so callers can label partial results. Resume after the last
    emitted match (or last scanned row if none matched), never a discarded
    lookahead row, to preserve keyset order without duplicates or omissions.
    """
    page_limit = max(0, int(page_limit))
    if page_limit == 0:
        return [], None
    scan_budget = scope_filter_scan_budget() if scan_budget is None else max(1, int(scan_budget))
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    batch_cursor = start_cursor
    scanned_rows = 0
    bounded = False
    bound_reason = ""
    deadline = deadline_monotonic or (time.monotonic() + scope_filter_deadline_seconds())
    last_scanned: dict[str, Any] | None = None
    while len(matches) <= page_limit:
        if scanned_rows >= scan_budget:
            bounded = True
            bound_reason = "scan_budget"
            break
        if time.monotonic() >= deadline:
            bounded = True
            bound_reason = "deadline"
            break
        items, batch_next = fetch_batch(batch_cursor, min(batch_size, scan_budget - scanned_rows))
        for current_row, enriched in items:
            if scanned_rows >= scan_budget or time.monotonic() >= deadline:
                bounded = True
                bound_reason = "scan_budget" if scanned_rows >= scan_budget else "deadline"
                break
            scanned_rows += 1
            last_scanned = current_row
            if predicate(enriched):
                matches.append((current_row, enriched))
                if len(matches) > page_limit:
                    break
        if bounded or len(matches) > page_limit or batch_next is None:
            break
        batch_cursor = batch_next
    return _scope_page_result(matches, page_limit, last_scanned, bounded, bound_reason, scanned_rows, scan_budget, sort, metadata)


def _scope_page_result(
    matches: list[tuple[dict[str, Any], dict[str, Any]]],
    page_limit: int,
    last_scanned: dict[str, Any] | None,
    bounded: bool,
    bound_reason: str,
    scanned_rows: int,
    scan_budget: int,
    sort: str,
    metadata: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], str | None]:
    has_more = len(matches) > page_limit or bounded
    emitted = matches[:page_limit]
    payloads = [enriched for (_current, enriched) in emitted]
    next_cursor = None
    if has_more:
        cursor_row = emitted[-1][0] if emitted else last_scanned
        if cursor_row is not None:
            next_cursor = cursor_from_current_row(cursor_row, sort=sort)
    if metadata is not None:
        # Accumulate: one response may drive several walks (merged scan+bulk).
        metadata["scanned_rows"] = int(metadata.get("scanned_rows") or 0) + scanned_rows
        metadata["scan_budget"] = scan_budget
        metadata["truncated"] = bool(metadata.get("truncated")) or bounded
        metadata["reason"] = bound_reason or str(metadata.get("reason") or "")
    return payloads, next_cursor


def _severity_rank(payload: dict[str, Any]) -> int:
    return severity_policy_rank(str(payload.get("severity", "")))


def _cvss_value(payload: dict[str, Any]) -> float:
    try:
        return float(payload.get("cvss_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _page_signal(row: dict[str, Any], sort: str) -> float:
    """Return the single descending sort signal for ``list_page``."""
    if sort == "cvss":
        return _cvss_value(row)
    if sort == "severity":
        return float(_severity_rank(row))
    # effective_reach (default): trust the composite materialised at ingest
    # (``_REACH_SORT_KEY``) instead of re-deriving it per row on the read path.
    # Fall back to deriving it for any row that predates materialisation (#4049).
    cached = row.get(_REACH_SORT_KEY)
    if cached is not None:
        try:
            return float(cached)
        except (TypeError, ValueError):
            pass
    return compute_effective_reach_score(row)


def _page_sort_key(sort: str) -> Callable[[dict[str, Any]], float]:
    """Return a Python sort key mirroring the SQL ordering of ``list_page``.

    Descending on the requested signal only. Python's stable sort preserves
    ingest order for ties, which matches the SQL ``ORDER BY <signal> DESC,
    ordinal ASC`` tiebreak used by the persistent backends.
    """
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
    return lambda row: -_page_signal(row, normalized)


def _strip_reach_sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop the private ingest-materialised reach scalar from returned payloads.

    ``hydrate_finding_payloads_memory`` returns fresh dict copies, so popping
    here never mutates the stored bucket — it just keeps ``_REACH_SORT_KEY`` an
    internal sort scalar and out of the API response (#4049).
    """
    for row in rows:
        row.pop(_REACH_SORT_KEY, None)
    return rows


def _filter_hub_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
) -> list[dict[str, Any]]:
    if origin is not None:
        rows = [r for r in rows if r.get("origin") == origin]
    if severity is not None:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity", "")).lower() == sev]
    if scan_id is not None:
        rows = [r for r in rows if str(r.get("batch_id") or r.get("scan_id") or "") == scan_id]
    return rows


def _severity_breakdown_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for row in rows:
        sev = str(row.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _severity_breakdown_from_current_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Per-severity counts over current-state rows.

    Resolves severity the same way :func:`_filter_current_rows` does (top-level
    column first, then ``payload``) so the buckets match ``list_current_page``'s
    ``severity=`` COUNT exactly.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for row in rows:
        sev = str(row.get("severity") or (row.get("payload") or {}).get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _payload_is_kev(payload: Mapping[str, Any] | None) -> bool:
    """Return True when a finding payload carries a CISA-KEV flag.

    The hub normalises ``cisa_kev`` to ``is_kev`` on store, but accept either so
    a freshly-ingested or hydrated payload both resolve — matching what the
    /v1/findings drill shows per row."""
    if not payload:
        return False
    return bool(payload.get("is_kev") or payload.get("cisa_kev"))


def _kev_json_cond_sqlite(col: str) -> str:
    """SQLite predicate: the KEV flag on a JSON column (bool ``true`` or string)."""
    return f"json_extract({col}, '$.is_kev') IN (1, 'true', 'True', '1') OR json_extract({col}, '$.cisa_kev') IN (1, 'true', 'True', '1')"


def _current_kev_count_from_rows(rows: Iterable[dict[str, Any]]) -> int:
    """Count current-state rows whose (hydrated) payload is CISA-KEV flagged."""
    return sum(1 for row in rows if _payload_is_kev(row.get("payload")))


def _framework_slug_counts_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    from agent_bom.compliance_coverage import normalize_framework_slug

    counts: dict[str, int] = {}
    for row in rows:
        for slug in row.get("applicable_frameworks") or []:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + 1
    return counts


def _redact_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact one hub finding payload for persistence."""
    from agent_bom.finding_scope import safe_finding_response_payload

    # Path sources are stamped at read time only; a stored copy could forge corroboration.
    safe = safe_finding_response_payload(without_fields(payload, SERVER_STAMPED_REACH_FIELDS))
    clean = {key: value for key, value in without_fields(safe, SERVER_STAMPED_REACH_FIELDS).items() if value is not None}
    # Persisting the empty agent-list default adds no evidence and defeats compaction.
    if not clean.get("graph_reachable_from_agents"):
        clean.pop("graph_reachable_from_agents", None)
    # Classification and lane are derived on read; persisting them wastes
    # space and can drift from the canonical classifiers after an upgrade.
    clean.pop("finding_class", None)
    clean.pop("lane", None)
    # No deadline carries no provenance to preserve; recompute the unavailable
    # response marker on read instead of repeating it in every ledger payload.
    if clean.get("sla_due_at_source") == "unavailable":
        clean.pop("sla_due_at_source", None)
    # Preserve the established hub identity contract: client-supplied
    # canonical_id is not authoritative at ingest; resolve_canonical_id() uses
    # the vetted finding id/content key after redaction.
    clean.pop("canonical_id", None)
    if "id" not in clean and "id" in payload:
        clean["id"] = str(payload["id"])
    if "source" not in clean and "source" in payload:
        clean["source"] = str(payload["source"])
    for key in ("origin", "ingest_source", "batch_id", "bulk_ordinal", "intel_ref", "framework_ref"):
        if key not in clean and key in payload:
            clean[key] = payload[key]
    return clean


def _redact_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop tier-B fields before any compliance-hub finding is stored.

    The hub is a tier-A sink — findings are exported, queried by auditors,
    and held indefinitely. See issue #2261.
    """
    redacted: list[dict[str, Any]] = []
    for payload in findings:
        if not isinstance(payload, dict):
            continue
        redacted.append(_redact_finding(payload))
    return redacted


def _sqlite_current_order_clause(sort: str) -> str:
    """Compatibility export for the shared indexed current-state order."""
    return finding_order_clause("sqlite", sort)


def _postgres_current_order_clause(sort: str) -> str:
    """Postgres ORDER BY for ``hub_findings_current``, served by the ``COLLATE "C"`` sort indexes."""
    return finding_order_clause("postgres", sort)


def _desc_tie_break(value: str) -> tuple[int, ...]:
    """Lex descending tie-breaker aligned with SQL ``last_seen DESC``."""
    return tuple(-ord(ch) for ch in value)


def _current_page_sort_key(sort: str) -> Callable[[dict[str, Any]], _CurrentPageSortKey]:
    """Sort key for in-memory current-state pages (descending primary signal)."""
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"

    def _key(row: dict[str, Any]) -> _CurrentPageSortKey:
        tie = str(row.get("last_seen") or "")
        canonical = str(row.get("canonical_id") or "")
        if normalized == "ordinal":
            raw_ordinal = row.get("ledger_ordinal")
            ordinal = _LEDGER_ORDINAL_SENTINEL if raw_ordinal is None else int(raw_ordinal)
            return (ordinal, str(row.get("first_seen") or ""), canonical)
        if normalized == "cvss":
            primary = cvss_sort_value(row.get("cvss_score"))
        elif normalized == "severity":
            primary = float(row.get("severity_rank") or 0)
        else:
            primary = float(row.get("effective_reach_score") or 0.0)
        return (-primary, _desc_tie_break(tie), canonical)

    return _key


def _filter_current_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
    since: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    if status is not None:
        rows = [r for r in rows if status_matches(r, status)]
    if origin is not None:
        rows = [r for r in rows if (r.get("payload") or {}).get("origin") == origin]
    if severity is not None:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity") or (r.get("payload") or {}).get("severity", "")).lower() == sev]
    if scan_id is not None:
        rows = [
            r for r in rows if str((r.get("payload") or {}).get("batch_id") or (r.get("payload") or {}).get("scan_id") or "") == scan_id
        ]
    if since:
        rows = [r for r in rows if str(r.get("last_seen") or "") >= since]
    return rows
