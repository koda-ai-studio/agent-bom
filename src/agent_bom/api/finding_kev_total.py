"""Exact totals for scoped findings filters.

KEV is the exec headline, and the hub already counts it with the same
tenant/window/lifecycle predicates the overview uses. Other scope filters
(framework, control, q, provider, ...) are matched against payload fields in
batches; a first page counts the bulk half's matches once, under a row budget,
so it reports an exact total instead of ``null`` unless the budget is spent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def exact_kev_total(query: Any, scan_rows: int, bulk_list: Callable[..., Any], store: Any) -> int | None:
    """Scan-half matches plus the hub's indexed KEV count, or ``None`` when not exact.

    ``query`` is the route's validated ``_FindingListQuery``; only a first page
    (no cursor) of a KEV-only scope without severity or scan pinning qualifies.
    """
    scope = dict(query.scope_filters)
    if set(scope) != {"kev"} or query.severity or query.scan_id or query.cursor:
        return None
    counter = getattr(store, "current_kev_count", None)
    if not callable(counter):
        return None
    window = {"since": query.window_since, "status": query.status_key}
    hub_kev = int(counter(query.tenant_id, origin="bulk_ingest", **window))
    if scope["kev"] == "true":
        return scan_rows + hub_kev
    probe = bulk_list(query.tenant_id, limit=1, offset=0, sort=query.sort_key, origin="bulk_ingest", include_total=True, **window)
    hub_total = probe[1] if len(probe) > 1 else None
    if not isinstance(hub_total, int):
        return None
    return scan_rows + max(0, hub_total - hub_kev)


SCOPED_COUNT_BUDGET = 20_000


def exact_scoped_total(query: Any, scan_rows: int, bulk_list: Callable[..., Any]) -> int | None:
    """Scan-half matches (already scope-filtered) plus a budgeted count of matching bulk rows.

    Only a first page qualifies; continuations keep their resume totals. ``None``
    when the bulk walk hits the budget or reports a truncated scope read.
    """
    if query.cursor or not query.scope_filters:
        return None
    metadata: dict[str, Any] = {}
    result = bulk_list(
        query.tenant_id,
        limit=SCOPED_COUNT_BUDGET,
        offset=0,
        sort=query.sort_key,
        severity=query.severity,
        scan_id=query.scan_id,
        origin="bulk_ingest",
        include_total=False,
        since=query.window_since,
        status=query.status_key,
        scope=dict(query.scope_filters),
        scope_metadata=metadata,
    )
    rows, next_cursor = result[0], (result[2] if len(result) > 2 else None)
    if next_cursor or metadata.get("truncated") or len(rows) >= SCOPED_COUNT_BUDGET:
        return None
    return scan_rows + len(rows)
