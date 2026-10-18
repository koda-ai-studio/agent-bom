"""Bounded native import orchestration over the existing runtime event store.

Failures leave the last committed cursor intact. Observations, rollups and each
page checkpoint share the store's transaction. A provider cursor is a traversal
boundary, not a guarantee that the upstream window is an immutable snapshot.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
from agent_bom.api.runtime_event_store import RuntimeEventStore
from agent_bom.api.storage.runtime_trace_imports import TraceImportCheckpoint, TraceImportConflictError
from agent_bom.trace_connectors import NativeTracePage, TraceConnectorError, TraceConnectorResponseTooLargeError, _TraceConnectorHTTPError


def import_native_pages(
    store: RuntimeEventStore,
    *,
    scope: TraceImportScope,
    fetch: Callable[..., NativeTracePage],
    import_id: str | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    max_pages: int = 1,
    now: str | None = None,
    on_page: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Commit up to five pages; response counts describe this request only.

    The caller resolves scope through the authenticated connection broker, never
    from vendor row metadata or browser-supplied source/project identifiers.
    Rejected rows are counted and coverage remains partial even after traversal
    completes. Retrying uses the same import_id; a new pull re-reads a new window.
    """
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= 5:
        raise ValueError("Trace import max_pages must be between 1 and 5")
    moment = datetime.fromisoformat(now.replace("Z", "+00:00")) if now else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("Trace import time requires a timezone")
    collected_at = moment.astimezone(timezone.utc).isoformat()
    current = _resolve_checkpoint(store, scope, import_id, window_start, window_end, moment, collected_at)
    counts = {"fetched": 0, "imported": 0, "updated": 0, "unchanged": 0, "rejected": 0, "committed_pages": 0, "failed_pages": 0}
    rejected: Counter[str] = Counter()
    error: dict[str, Any] | None = None
    for _ in range(max_pages):
        if current.complete:
            break
        try:
            page = fetch(window_start=current.window_start, window_end=current.window_end, cursor=current.cursor)
        except TraceConnectorError as exc:
            counts["failed_pages"] += 1
            error = _provider_error(exc)
            break
        cursor_history = _next_cursor_history(current, page.cursor)
        if on_page is not None:
            on_page(page.payload)
        prepared = prepare_trace_page(page.payload, scope=scope, collected_at=collected_at)
        rejected_count = sum(prepared.rejected.values())
        next_checkpoint = replace(
            current,
            revision=current.revision + 1,
            cursor=page.cursor,
            complete=page.cursor is None,
            updated_at=collected_at,
            rejected_count=current.rejected_count + rejected_count,
            cursor_history=cursor_history,
        )
        committed = store.commit_trace_page(next_checkpoint, prepared.observations, expected_revision=current.revision)
        counts["fetched"] += page.fetched
        counts["imported"] += committed.inserted
        counts["updated"] += committed.updated
        counts["unchanged"] += committed.unchanged
        counts["rejected"] += rejected_count
        counts["committed_pages"] += 1
        rejected.update(prepared.rejected)
        current = next_checkpoint
    return {
        "import_id": current.import_id,
        "revision": current.revision,
        "complete": current.complete,
        "status": "complete" if current.complete else "partial" if current.revision > 1 else "pending",
        "coverage": "window_traversed" if current.complete and not current.rejected_count else "partial",
        "window_start": current.window_start,
        "window_end": current.window_end,
        "scope": asdict(scope),
        "counts_scope": "this_request",
        "counts": counts,
        "rejected_reasons": dict(rejected),
        "total_rejected": current.rejected_count,
        "error": error,
        "content_retained": False,
    }


def _resolve_checkpoint(
    store: RuntimeEventStore,
    scope: TraceImportScope,
    import_id: str | None,
    window_start: str | None,
    window_end: str | None,
    moment: datetime,
    collected_at: str,
) -> TraceImportCheckpoint:
    scope_key = hashlib.sha256(json.dumps(scope.identity_scope(), sort_keys=True).encode()).hexdigest()
    if import_id is not None:
        if not isinstance(import_id, str) or not import_id or len(import_id) > 512:
            raise ValueError("Trace import is unavailable")
        current = store.get_trace_import(scope.tenant_id, import_id)
        if current is None:
            raise ValueError("Trace import is unavailable")
        if current.scope_key != scope_key:
            raise ValueError("Trace import source scope changed; start a new import")
        if window_start is not None or window_end is not None:
            raise ValueError("A resumed trace import uses its saved window")
    else:
        end = datetime.fromisoformat(window_end.replace("Z", "+00:00")) if window_end else moment
        start = datetime.fromisoformat(window_start.replace("Z", "+00:00")) if window_start else end - timedelta(days=1)
        if start.tzinfo is None or end.tzinfo is None or not timedelta(0) < end - start <= timedelta(days=31):
            raise ValueError("Trace import requires a timezone-aware window of at most 31 days")
        current = TraceImportCheckpoint(
            tenant_id=scope.tenant_id,
            import_id=f"trace-import-{uuid.uuid4().hex}",
            revision=1,
            window_start=start.astimezone(timezone.utc).isoformat(),
            window_end=end.astimezone(timezone.utc).isoformat(),
            updated_at=collected_at,
            scope_key=scope_key,
        )
        # Save the fixed window before the first network page so even first-page
        # failures can resume without drifting their coverage boundary.
        store.commit_trace_page(current, [], expected_revision=0)
    return current


def _next_cursor_history(current: TraceImportCheckpoint, cursor: str | None) -> tuple[str, ...]:
    if cursor is None:
        return current.cursor_history
    digest = hashlib.sha256(cursor.encode()).hexdigest()
    if cursor == current.cursor or digest in current.cursor_history or len(current.cursor_history) >= 1000:
        raise TraceImportConflictError("Provider cursor cycle or page limit reached; checkpoint retained")
    return (*current.cursor_history, digest)


def _provider_error(exc: TraceConnectorError) -> dict[str, Any]:
    if isinstance(exc, TraceConnectorResponseTooLargeError):
        return {"code": "response_too_large", "retryable": False}
    status = exc.status if isinstance(exc, _TraceConnectorHTTPError) else None
    error: dict[str, Any] = {
        "code": "rate_limited" if status == 429 else "provider_unavailable",
        "retryable": status not in {400, 401, 403, 404, 410},
    }
    if error["retryable"] and isinstance(exc, _TraceConnectorHTTPError) and exc.retry_after > 0:
        error["retry_after_seconds"] = exc.retry_after
    return error
