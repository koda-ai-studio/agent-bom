"""Compliance hub memory implementation."""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.finding_cursor import (
    cursor_from_current_row,
    decode_finding_cursor,
    row_is_after_cursor,
)
from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score
from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    current_state_overlay,
    hydrate_current_payload,
    resolve_ledger_finding_id,
)
from agent_bom.api.hub_reference_store import (
    hydrate_finding_payloads_memory,
    normalize_finding_payload_for_store,
)
from agent_bom.api.storage.hub_contract import (
    _LEDGER_ORDINAL_SENTINEL,
    _LIST_PAGE_SORTS,
    _REACH_SORT_KEY,
    IN_MEMORY_SORT_CEILING,
    FindingCursorPage,
    FindingPage,
    _HubFindingRows,
    _logger,
)
from agent_bom.api.storage.hub_filters import (
    _current_kev_count_from_rows,
    _current_page_sort_key,
    _filter_current_rows,
    _filter_hub_rows,
    _framework_slug_counts_from_rows,
    _page_sort_key,
    _redact_finding,
    _redact_findings,
    _severity_breakdown_from_current_rows,
    _severity_breakdown_from_rows,
    _strip_reach_sort,
    collect_scope_filtered_page,
    scope_filter_batch_size,
)
from agent_bom.api.storage.hub_schema import _now_utc_iso
from agent_bom.core.tenancy import require_explicit_tenant_id


class InMemoryComplianceHubStore:
    """Process-local store. Ephemeral; tests + single-node demos only.

    Scale ceiling: reads copy + re-sort a tenant's whole row list per request
    (see ``IN_MEMORY_SORT_CEILING``). This backend is intentionally the demo /
    single-node path; production deployments use the SQLite or Postgres backend,
    which sort in the query plan. A tenant that grows past the ceiling logs a
    one-time warning rather than silently degrading.
    """

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}
        # Tenants already warned about crossing IN_MEMORY_SORT_CEILING, so the
        # guard logs once per tenant instead of on every paged read.
        self._sort_ceiling_warned: set[str] = set()
        # Maps finding_id -> ingest-order slot so a resend of the same
        # (tenant_id, finding_id) refreshes its row in place instead of
        # appending a duplicate (idempotent ingest, mirrors the SQL backends).
        self._slots: dict[str, dict[str, int]] = {}
        self._current: dict[str, dict[str, dict[str, Any]]] = {}
        self._current_observations: dict[str, set[tuple[str, str]]] = {}
        self._overview_revisions: dict[str, int] = {}
        self._lock = threading.Lock()

    def _invalidate_ingest_caches(self, tenant_id: str) -> None:
        from agent_bom.api import hub_overview_cache
        from agent_bom.api.findings_count_cache import invalidate_tenant

        with self._lock:
            self._overview_revisions[tenant_id] = self._overview_revisions.get(tenant_id, 0) + 1
        invalidate_tenant(tenant_id)
        hub_overview_cache.invalidate_tenant(tenant_id, source_is_memory=True)

    def overview_evidence_revision(self, tenant_id: str) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            return self._overview_revisions.get(tenant_id, 0)

    def _add_locked(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append the batch to the ledger. Caller MUST hold ``self._lock``."""
        bucket = self._by_tenant.setdefault(tenant_id, [])
        slots = self._slots.setdefault(tenant_id, {})
        for payload in findings:
            if not isinstance(payload, dict):
                continue
            slim = normalize_finding_payload_for_store(tenant_id, payload)
            stored = _redact_finding(slim)
            # Materialise the effective-reach composite once at ingest so the
            # read-path sort never re-derives it per row (#4049). Mirrors the
            # SQL backends materialising the ``effective_reach_score`` column.
            stored[_REACH_SORT_KEY] = compute_effective_reach_score(stored)
            finding_id = str(stored.get("id") or "")
            if finding_id and finding_id in slots:
                # Refresh payload, keep original ingest position.
                from agent_bom.graph.sla import carry_finding_sla

                bucket[slots[finding_id]] = carry_finding_sla(stored, bucket[slots[finding_id]])
                continue
            if finding_id:
                slots[finding_id] = len(bucket)
            bucket.append(stored)
        return len(bucket)

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            total = self._add_locked(tenant_id, findings)
        if findings:
            self._invalidate_ingest_caches(tenant_id)
        return total

    def ingest_batch_atomic(
        self,
        tenant_id: str,
        findings: list[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str,
        reconcile_absent: bool,
        present_canonical_ids: set[str],
    ) -> tuple[int, int]:
        """Ledger append + current upsert (+ reconcile) as one atomic unit.

        The three writes ran as separate lock acquisitions, so a failure between
        them left the ledger appended while current-state stayed behind. Here all
        three run under a single lock; on failure the pre-batch snapshot is
        restored so nothing is partially applied. Mirrors the SQL backends'
        single-transaction seam. Returns ``(new_total, reconciled)``.
        """
        tenant_id = require_explicit_tenant_id(tenant_id)
        clean = _redact_findings(findings)
        with self._lock:
            snap_bucket = list(self._by_tenant.get(tenant_id, []))
            snap_slots = dict(self._slots.get(tenant_id, {}))
            snap_current = {k: dict(v) for k, v in self._current.get(tenant_id, {}).items()}
            snap_obs = set(self._current_observations.get(tenant_id, set()))
            try:
                total = self._add_locked(tenant_id, findings)
                self._upsert_current_locked(
                    tenant_id,
                    clean,
                    observed_at=observed_at,
                    batch_id=batch_id,
                    source=source,
                )
                reconciled = 0
                if reconcile_absent:
                    reconciled = self._reconcile_locked(
                        tenant_id,
                        present_canonical_ids=present_canonical_ids,
                        observed_at=observed_at,
                        scope_source=source,
                    )
            except Exception:
                self._by_tenant[tenant_id] = snap_bucket
                self._slots[tenant_id] = snap_slots
                self._current[tenant_id] = snap_current
                self._current_observations[tenant_id] = snap_obs
                raise
        if findings or reconcile_absent:
            self._invalidate_ingest_caches(tenant_id)
        return total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _strip_reach_sort(hydrate_finding_payloads_memory(tenant_id, rows))

    def _guard_sort_ceiling(self, tenant_id: str, row_count: int) -> None:
        """Warn once per tenant when the whole-tenant re-sort ceiling is crossed.

        The in-memory backend re-sorts a tenant's entire row list on every paged
        read. Past ``IN_MEMORY_SORT_CEILING`` that is a real per-request cost;
        surface it (once per tenant) instead of degrading silently — a SQL
        backend sorts in the query plan and should be used at that scale.
        """
        if row_count <= IN_MEMORY_SORT_CEILING or tenant_id in self._sort_ceiling_warned:
            return
        self._sort_ceiling_warned.add(tenant_id)
        _logger.warning(
            "InMemoryComplianceHubStore is sorting %d rows per read (ceiling %d); "
            "this demo/single-node backend re-sorts the whole tenant per request — "
            "use the SQLite or Postgres backend at this scale.",
            row_count,
            IN_MEMORY_SORT_CEILING,
        )

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
    ) -> FindingPage:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        self._guard_sort_ceiling(tenant_id, len(rows))
        rows = _filter_hub_rows(rows, severity=severity, scan_id=scan_id, origin=origin)
        total = len(rows) if include_total else None
        if sort != "ordinal":
            rows.sort(key=_page_sort_key(sort))
        if offset:
            rows = rows[offset:]
        if limit >= 0:
            rows = rows[:limit]
        return _strip_reach_sort(hydrate_finding_payloads_memory(tenant_id, rows)), total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _severity_breakdown_from_rows(rows)

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        with self._lock:
            rows = list(self._current.get(tenant_id, {}).values())
        rows = _filter_current_rows(rows, severity=None, scan_id=None, origin=origin, since=since, status=status)
        return _severity_breakdown_from_current_rows(rows)

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> int:
        with self._lock:
            rows = [dict(r) for r in self._current.get(tenant_id, {}).values()]
        rows = _filter_current_rows(rows, severity=None, scan_id=None, origin=origin, since=since, status=status)
        # Current-state rows keep an overlay-only payload; the KEV flag lives in
        # the ledger payload, so hydrate first (same source the drill reads).
        rows = self._hydrate_current_rows(tenant_id, rows)
        return _current_kev_count_from_rows(rows)

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        rows = hydrate_finding_payloads_memory(tenant_id, rows)
        return _framework_slug_counts_from_rows(rows)

    def current_failing_framework_slug_counts(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        with self._lock:
            rows = [dict(r) for r in self._current.get(tenant_id, {}).values()]
        rows = _filter_current_rows(rows, severity=None, scan_id=None, origin=origin, since=since, status=status)
        rows = [row for row in rows if str(row.get("severity") or "").lower() in {"critical", "high"}]
        hydrated = self._hydrate_current_rows(tenant_id, rows)
        return _framework_slug_counts_from_rows(row.get("payload") or {} for row in hydrated)

    def count(self, tenant_id: str) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            return len(self._by_tenant.get(tenant_id, []))

    def clear(self, tenant_id: str) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            removed = len(self._by_tenant.get(tenant_id, []))
            had_current = bool(self._current.get(tenant_id))
            self._by_tenant[tenant_id] = []
            self._slots[tenant_id] = {}
            self._current.pop(tenant_id, None)
            self._current_observations.pop(tenant_id, None)
        if removed or had_current:
            self._invalidate_ingest_caches(tenant_id)
        return removed

    def _upsert_current_locked(
        self,
        tenant_id: str,
        clean: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        """Upsert current-state for a redacted batch. Caller MUST hold the lock."""
        from agent_bom.api.finding_lifecycle import (
            apply_observation_to_current,
            lifecycle_metrics,
            resolve_canonical_id,
        )

        now = _now_utc_iso()
        current = self._current.setdefault(tenant_id, {})
        observations = self._current_observations.setdefault(tenant_id, set())
        for payload in clean:
            canonical = resolve_canonical_id(payload, source=source)
            obs_key = (canonical, batch_id)
            if obs_key in observations:
                continue
            observations.add(obs_key)
            existing = current.get(canonical)
            if existing is not None:
                existing = dict(existing)
                slot = self._slots.get(tenant_id, {}).get(str(existing.get("ledger_finding_id") or ""))
                ledger = self._by_tenant.get(tenant_id, [])
                if slot is not None and slot < len(ledger):
                    existing["payload"] = hydrate_current_payload(
                        existing, ledger_payloads={str(existing["ledger_finding_id"]): ledger[slot]}
                    )
            merged = apply_observation_to_current(
                existing,
                canonical_id=canonical,
                observed_at=observed_at,
                metrics=lifecycle_metrics(payload),
                payload=payload,
                updated_at=now,
            )
            finding_id = resolve_ledger_finding_id(payload, canonical_id=canonical)
            if finding_id:
                merged["ledger_finding_id"] = finding_id
                merged["payload"] = current_state_overlay(merged["payload"])
                merged["ledger_ordinal"] = self._slots.get(tenant_id, {}).get(finding_id, _LEDGER_ORDINAL_SENTINEL)
            else:
                merged["ledger_ordinal"] = _LEDGER_ORDINAL_SENTINEL
            current[canonical] = merged

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        tenant_id = require_explicit_tenant_id(tenant_id)
        clean = _redact_findings(findings)
        with self._lock:
            self._upsert_current_locked(
                tenant_id,
                clean,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
        if clean:
            self._invalidate_ingest_caches(tenant_id)

    def _ledger_payload_map(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        slots = self._slots.get(tenant_id, {})
        bucket = self._by_tenant.get(tenant_id, [])
        out: dict[str, dict[str, Any]] = {}
        for finding_id in finding_ids:
            idx = slots.get(finding_id)
            if idx is not None and 0 <= idx < len(bucket):
                out[finding_id] = hydrate_finding_payloads_memory(tenant_id, [bucket[idx]])[0]
        return out

    def _hydrate_current_rows(self, tenant_id: str, rows: _HubFindingRows) -> _HubFindingRows:
        ledger_map = batch_ledger_payloads(
            lambda ids: self._ledger_payload_map(tenant_id, ids),
            [str(row.get("ledger_finding_id") or "") for row in rows],
        )
        hydrated: list[dict[str, Any]] = []
        for row in rows:
            hydrated_row = dict(row)
            hydrated_row["payload"] = hydrate_current_payload(row, ledger_payloads=ledger_map)
            hydrated.append(hydrated_row)
        return hydrated

    def lookup_current_ids(
        self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None
    ) -> set[str]:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            current = self._current.get(tenant_id, {})
            found = set()
            for key in canonical_ids:
                row = current.get(key)
                if row is None:
                    continue
                payload = row.get("payload") or {}
                if scan_id is not None and str(payload.get("batch_id") or payload.get("scan_id") or "") != scan_id:
                    continue
                if origin is not None and payload.get("origin") != origin:
                    continue
                found.add(key)
            return found

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            row = self._current.get(tenant_id, {}).get(canonical_id)
            if not row:
                return None
            hydrated = self._hydrate_current_rows(tenant_id, [dict(row)])
            return hydrated[0]

    def list_current_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
        scope_metadata: dict[str, Any] | None = None,
    ) -> FindingCursorPage:
        tenant_id = require_explicit_tenant_id(tenant_id)
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        normalized_sort = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
        if scope:
            return self._list_current_page_scoped(
                tenant_id,
                limit=limit,
                sort=normalized_sort,
                severity=severity,
                scan_id=scan_id,
                origin=origin,
                cursor=cursor,
                since=since,
                scope=scope,
                status=status,
                scope_metadata=scope_metadata,
            )
        with self._lock:
            rows = list(self._current.get(tenant_id, {}).values())
        rows = _filter_current_rows(rows, severity=severity, scan_id=scan_id, origin=origin, since=since, status=status)
        total = len(rows) if include_total else None
        rows.sort(key=_current_page_sort_key(normalized_sort))
        if cursor:
            primary, last_seen, canonical_id = decode_finding_cursor(cursor, expected_sort=normalized_sort)
            rows = [
                row
                for row in rows
                if row_is_after_cursor(
                    row,
                    sort=normalized_sort,
                    primary=primary,
                    last_seen=last_seen,
                    canonical_id=canonical_id,
                )
            ]
        elif offset:
            rows = rows[offset:]
        page_limit = max(0, int(limit))
        fetch_limit = page_limit + 1 if page_limit >= 0 else page_limit
        if page_limit >= 0:
            chunk = rows[:fetch_limit]
            has_more = len(chunk) > page_limit
            rows = chunk[:page_limit]
        else:
            has_more = False
        rows = self._hydrate_current_rows(tenant_id, [dict(row) for row in rows])
        enriched = [enriched_finding_payload(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            next_cursor = cursor_from_current_row(rows[-1], sort=normalized_sort)
        return enriched, total, next_cursor

    def _list_current_page_scoped(
        self,
        tenant_id: str,
        *,
        limit: int,
        sort: str,
        severity: str | None,
        scan_id: str | None,
        origin: str | None,
        cursor: str | None,
        since: str | None,
        scope: Mapping[str, str],
        status: str | None = None,
        scope_metadata: dict[str, Any] | None = None,
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload
        from agent_bom.finding_scope import row_matches_scope

        # The process-local store is already fully materialized; a single batch
        # (the whole filtered+sorted stream after the cursor) feeds the shared
        # keyset collector, so scope semantics and next_cursor emission match the
        # SQL backends exactly. total is None under a scope filter (approximate).
        def fetch_batch(batch_cursor: str | None, _batch_limit: int) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]:
            with self._lock:
                rows = list(self._current.get(tenant_id, {}).values())
            rows = _filter_current_rows(rows, severity=severity, scan_id=scan_id, origin=origin, since=since, status=status)
            rows.sort(key=_current_page_sort_key(sort))
            if batch_cursor:
                primary, last_seen, canonical_id = decode_finding_cursor(batch_cursor, expected_sort=sort)
                rows = [
                    row
                    for row in rows
                    if row_is_after_cursor(row, sort=sort, primary=primary, last_seen=last_seen, canonical_id=canonical_id)
                ]
            hydrated = self._hydrate_current_rows(tenant_id, [dict(row) for row in rows])
            pairs = [(row, enriched_finding_payload(row)) for row in hydrated]
            return pairs, None

        page_limit = max(0, int(limit))
        payloads, next_cursor = collect_scope_filtered_page(
            fetch_batch,
            predicate=lambda payload: row_matches_scope(payload, scope),
            page_limit=page_limit,
            start_cursor=cursor,
            sort=sort,
            batch_size=scope_filter_batch_size(page_limit),
            metadata=scope_metadata,
        )
        return payloads, None, next_cursor

    def _reconcile_locked(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        """Resolve absent open findings. Caller MUST hold ``self._lock``."""
        now = _now_utc_iso()
        updated = 0
        current = self._current.setdefault(tenant_id, {})
        for canonical_id, row in list(current.items()):
            if str(row.get("status") or "") not in ("open", "reopened"):
                continue
            if canonical_id in present_canonical_ids:
                continue
            payload = row.get("payload") or {}
            payload_scope = str(payload.get("ingest_source") or payload.get("source") or "")
            if scope_source is not None and payload_scope != scope_source:
                continue
            merged = dict(row)
            merged["status"] = "resolved"
            merged["resolved_at"] = observed_at
            merged["updated_at"] = now
            current[canonical_id] = merged
            updated += 1
        return updated

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._lock:
            updated = self._reconcile_locked(
                tenant_id,
                present_canonical_ids=present_canonical_ids,
                observed_at=observed_at,
                scope_source=scope_source,
            )
        if updated:
            self._invalidate_ingest_caches(tenant_id)
        return updated
