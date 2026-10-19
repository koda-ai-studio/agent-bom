"""Exact totals for the ``?kev=`` findings filter.

Generic scope filters are matched against payload fields in batches, so their
totals are approximate. KEV is the exec headline, and the hub already counts
it with the same tenant/window/lifecycle predicates the overview uses, so a
KEV-only read can report the exact total instead of ``null``.
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
