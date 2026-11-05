"""Bounded cleanup-tick pass that repairs CVE records and applies a trusted KEV catalog.

A pass links current findings to CVE records, then walks those records. It starts
hourly per process, spans as many ticks as it needs, and writes only rows that
change, so replicas can run it at once. When no trusted catalog is available the pass
still reconciles column and payload, and every KEV flag is kept.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from agent_bom.api import compliance_hub_store, hub_overview_cache
from agent_bom.api.findings_count_cache import invalidate_tenant
from agent_bom.api.storage.cve_intel_reconcile import START, Cursor
from agent_bom.db.kev_catalog import KevCatalog, load_trusted_kev_catalog

_logger = logging.getLogger(__name__)

_BATCH_ROWS = 500
_TICK_BUDGET_SECONDS = 5.0
_PASS_INTERVAL_SECONDS = 3600.0


@dataclass
class _Pass:
    linking: bool = True
    after: Cursor = START
    catalog: KevCatalog | None = None
    started: bool = False
    next_start: float = 0.0


_state = _Pass()


def reset_cve_intel_pass() -> None:
    global _state
    _state = _Pass()


def _begin_pass() -> None:
    _state.linking, _state.after, _state.started = True, START, True
    _state.catalog = load_trusted_kev_catalog()
    if _state.catalog is None:
        _logger.info("KEV catalog sync skipped: no fresh, complete catalog on this replica; KEV flags kept")
    else:
        _logger.info(
            "KEV catalog sync: source=%s version=%s entries=%d",
            _state.catalog.source,
            _state.catalog.version,
            len(_state.catalog.entries),
        )


def _step(store: object, batch_rows: int) -> int:
    """One committed batch; returns the rows it handled and advances the pass."""
    if _state.linking:
        after, handled = store.link_cve_rows_batch(_state.after, batch_rows)  # type: ignore[attr-defined]
        if after is None:
            _state.linking, _state.after = False, START
        else:
            _state.after = after
        return int(handled)
    page = store.reconcile_cve_intel_batch(_state.after, batch_rows, _state.catalog)  # type: ignore[attr-defined]
    for tenant in page.tenants:
        invalidate_tenant(tenant)
        hub_overview_cache.invalidate_tenant(tenant)
    if page.next_after is None:
        _state.started = False
        _state.next_start = time.monotonic() + _PASS_INTERVAL_SECONDS
    else:
        _state.after = page.next_after
    return int(page.seen)


def run_cve_intel_tick(*, budget_seconds: float = _TICK_BUDGET_SECONDS, batch_rows: int = _BATCH_ROWS) -> int:
    """Advance the current pass until the budget ends or it finishes; returns rows handled."""
    store = compliance_hub_store.get_compliance_hub_store()
    if not callable(getattr(store, "reconcile_cve_intel_batch", None)):
        return 0
    if not _state.started:
        if time.monotonic() < _state.next_start:
            return 0
        _begin_pass()
    deadline = time.monotonic() + budget_seconds
    total = 0
    while _state.started and time.monotonic() < deadline:
        total += _step(store, batch_rows)
    return total
