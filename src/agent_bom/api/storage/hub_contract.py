"""Compliance hub contract implementation."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score

_logger = logging.getLogger("agent_bom.api.compliance_hub_store")

RECONCILE_ABSENT_CHUNK = 500

IN_MEMORY_SORT_CEILING = 50_000

FindingPage = tuple[list[dict[str, Any]], int | None]

FindingCursorPage = tuple[list[dict[str, Any]], int | None, str | None]

_HubFindingRows = list[dict[str, Any]]

_CurrentPageSortKey = tuple[float | str, str | tuple[int, ...], str]

_LIST_PAGE_SORTS = ("effective_reach", "cvss", "severity", "ordinal")

_REACH_SORT_KEY = "__reach_sort__"

_SCOPE_FILTER_MIN_BATCH = 200

_SCOPE_FILTER_MAX_BATCH = 1000

_SCOPE_FILTER_SCAN_BUDGET = 20_000

_SCOPE_FILTER_DEADLINE_SECONDS = 1.5

_LIVE_STATUSES = ("open", "reopened")

STATUS_FILTERS = ("open", "resolved", "all")


class ComplianceHubStore(Protocol):
    """Append-only ledger of hub-ingested findings, scoped per tenant."""

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append findings for a tenant. Returns the new total count."""
        ...

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return every finding for a tenant in ingest order (oldest first).

        Deprecated for read-path use at scale: loads the full tenant into
        memory. Prefer :meth:`list_page` for API surfaces that paginate.
        Retained for posture aggregation and callers that genuinely need
        the whole tenant.
        """
        ...

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
        """Return a single page of findings plus the matching total.

        Pushes ``ORDER BY`` / ``LIMIT`` / ``OFFSET`` and the optional
        ``severity`` / ``scan_id`` / ``origin`` filters into the backend so
        the read path stays sub-linear at million-row scale. ``sort`` is one
        of ``effective_reach`` (default, indexed), ``cvss``, ``severity`` or
        ``ordinal`` (ingest order). Returns ``(rows, total)`` where ``total``
        counts all findings matching the filters, not just the page. When
        ``include_total`` is false the backend skips ``COUNT(*)`` and
        returns ``None`` for ``total``.
        """
        ...

    def count(self, tenant_id: str) -> int:
        """Return the count of findings for a tenant."""
        ...

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        """Return per-severity counts for hub findings without loading payloads."""
        ...

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        """Per-severity counts over CURRENT-STATE rows matching the drill-down.

        Mirrors :meth:`list_current_page`'s COUNT filters (tenant + ``origin``
        + ``since`` read-window + lifecycle ``status``) so the exec headline
        reconciles EXACTLY with ``/v1/findings`` — a click-through can never
        disagree with the headline. ``status`` (``open`` = live posture,
        open+reopened / ``resolved`` / ``all``; ``None`` = all history) keeps
        resolved findings out of the exec headline by default. Unlike
        :meth:`severity_breakdown` (which scans the append-only ledger, all-origin
        and unbounded), this reads ``hub_findings_current`` so retired / aged
        findings that linger in the ledger never inflate the exec numbers. An
        indexed ``GROUP BY`` — no payload hydration.
        """
        ...

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> int:
        """Count CURRENT-STATE findings flagged CISA-KEV, matching the drill.

        Same tenant + ``origin`` + ``since`` read-window + lifecycle predicates as
        :meth:`current_severity_breakdown`, so the exec KEV headline reconciles
        with the KEV rows /v1/findings shows. The KEV flag lives in the finding
        payload (inline, or in the CVE-intel reference for CVE findings), so the
        SQL backends resolve it from the current row, the ledger payload, and the
        intel reference — never scan-lane only.
        """
        ...

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        """Return per-framework slug counts from denormalised CSV columns."""
        ...

    def current_failing_framework_slug_counts(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        """Count framework mappings on live current high/critical findings."""
        ...

    def overview_evidence_revision(self, tenant_id: str) -> int:
        """Return the durable tenant mutation revision used by Overview caches."""
        ...

    def clear(self, tenant_id: str) -> int:
        """Remove all findings for a tenant. Returns the number removed."""
        ...

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        """Merge findings into the current-state lifecycle table (#3465 L1)."""
        ...

    def lookup_current_ids(
        self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None
    ) -> set[str]:
        """Batch identity lookup for reconciling scan observations with hub lifecycle state."""
        ...

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        """Return one current-state lifecycle row for tests and diagnostics."""
        ...

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
        """Return a page from ``hub_findings_current`` with lifecycle fields merged.

        ``since`` (ISO-8601 cutoff) bounds the page to findings whose
        ``last_seen`` is within the read window; ``None`` returns all history.

        ``status`` filters the sargable lifecycle column (``open`` = live posture
        open+reopened / ``resolved`` / ``all``; ``None`` = no predicate). It rides
        the ``status`` column (+ open partial index) and applies in BOTH the fast
        keyset path and the scoped batched path.

        ``scope`` (keys ``provider`` / ``account_ref`` / ``environment`` /
        ``domain``, already canonicalized/lowercased by the caller) applies the
        overlapping-lens scope predicate INSIDE the store on pre-enrichment
        current rows, batched + keyset-paged so a scoped page never materializes
        the whole tenant. When ``scope`` is set the exact O(table) ``COUNT(*)`` is
        skipped and ``total`` is ``None`` (the route flags it approximate); when
        ``scope`` is falsy behavior is unchanged.

        ``scope_metadata``, when supplied alongside ``scope``, is filled in place
        with the scope walk's completeness (``scanned_rows`` / ``scan_budget`` /
        ``truncated`` / ``reason``) so the caller can label a budget-bounded page
        partial instead of presenting it as an honest empty result.
        """
        ...

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        """Mark open findings absent from a scan batch as resolved at ``observed_at``."""
        ...


_SCHEMA_KEY = "compliance_hub"

_SCHEMA_VERSION = 3

_LEDGER_ORDINAL_SENTINEL = 9223372036854775807
