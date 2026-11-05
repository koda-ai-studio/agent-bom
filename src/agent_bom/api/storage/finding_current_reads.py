"""Snapshot-consistent current-finding reads shared by both SQL adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.finding_cursor import cursor_from_current_row, finding_keyset, finding_keyset_clause
from agent_bom.api.storage.finding_current import columns, hydrate_rows, parse_row
from agent_bom.api.storage.finding_materialized import LENS_BITS, VULN_CARD_BIT
from agent_bom.api.storage.sql import Dialect, SqlBackend, SqlSession
from agent_bom.core.severity import UNRATED_SEVERITY_BUCKET, empty_severity_histogram, severity_display_bucket
from agent_bom.core.tenancy import require_explicit_tenant_id

Page = tuple[list[dict[str, Any]], int | None, str | None]

# Mirrors severity_rank(normalize_severity(...)): an issue is as severe as its worst occurrence.
_ISSUE_RANK_SQL = (
    "CASE LOWER(TRIM(severity)) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'important' THEN 4 "
    "WHEN 'medium' THEN 3 WHEN 'moderate' THEN 3 WHEN 'low' THEN 2 WHEN 'minor' THEN 2 WHEN 'negligible' THEN 2 "
    "WHEN 'unimportant' THEN 2 WHEN 'info' THEN 1 WHEN 'informational' THEN 1 ELSE 0 END"
)
_ISSUE_RANK_BANDS = {5: "critical", 4: "high", 3: "medium", 2: "low"}

_KEV_INTEL_REFS = "SELECT cve_id FROM hub_cve_intel WHERE tenant_id = ? AND is_kev"
# ``intel_ref <> ''`` matches the partial index, so the planner probes KEV CVEs instead of scanning.
_KEV_VIA_INTEL = f"NOT kev_direct AND intel_ref <> '' AND intel_ref IN ({_KEV_INTEL_REFS})"


def issue_rank_band(rank: int) -> str:
    """Display band for a ``SEVERITY_RANK`` value; info and unknown are both unrated."""
    return _ISSUE_RANK_BANDS.get(rank, UNRATED_SEVERITY_BUCKET)


def has_ledger_column(tx: SqlSession, dialect: Dialect) -> bool:
    if dialect == "sqlite":
        return any(row[1] == "ledger_finding_id" for row in tx.execute("PRAGMA table_info(hub_findings_current)").fetchall())
    return bool(
        tx.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
            "AND table_name = 'hub_findings_current' AND column_name = 'ledger_finding_id'"
        ).fetchone()
    )


def current_order(sort: str, dialect: Dialect = "sqlite") -> str:
    """Use the same collated sort key as the opaque cursor predicate."""
    return finding_keyset(sort).order_by(dialect)


def filters(
    tenant: str, *, since: str | None, origin: str | None, severity: str | None, scan_id: str | None, status: str | None, kev: bool = False
) -> tuple[list[str], list[Any]]:
    from agent_bom.api.storage.hub_filters import status_sql_predicate

    where = ["tenant_id = ?"]
    params: list[Any] = [tenant]
    for predicate, value in [
        ("last_seen >= ?", since or None),
        ("origin = ?", origin),
        ("severity != '' AND LOWER(severity) = ?", severity.lower() if severity is not None else None),
        ("scan_id = ? AND scan_id != ''", scan_id),
    ]:
        if value is not None:
            where.append(predicate)
            params.append(value)
    predicate, values = status_sql_predicate(status)
    if predicate:
        where.append(predicate)
        params.extend(values)
    if kev:
        where.append(f"(kev_direct OR intel_ref IN ({_KEV_INTEL_REFS}))")
        params.append(tenant)
    return where, params


def fetch_page(
    tx: SqlSession,
    tenant: str,
    *,
    where: Sequence[str],
    params: Sequence[Any],
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    has_ledger: bool,
    dialect: Dialect,
) -> tuple[list[dict[str, Any]], str | None]:
    predicates, values = list(where), list(params)
    if cursor:
        clause, extra = finding_keyset_clause(dialect, sort, cursor)
        predicates.append(clause.removeprefix(" AND "))
        values.extend(extra)
    predicate = " AND ".join(predicates)
    values.append(limit + 1)
    limit_sql = "LIMIT ?"
    if offset and not cursor:
        limit_sql += " OFFSET ?"
        values.append(offset)
    rows = tx.execute(
        f"SELECT {columns(has_ledger)} FROM hub_findings_current WHERE {predicate} ORDER BY {current_order(sort, dialect)} {limit_sql}",  # nosec B608
        values,
    ).fetchall()  # nosec B608
    parsed = [parse_row(row, has_ledger_col=has_ledger) for row in rows[:limit]]
    hydrated = hydrate_rows(tx, tenant, parsed)
    next_cursor = cursor_from_current_row(hydrated[-1], sort=sort) if len(rows) > limit and hydrated else None
    return hydrated, next_cursor


def scoped_page(
    tx: SqlSession,
    tenant: str,
    *,
    where: Sequence[str],
    params: Sequence[Any],
    sort: str,
    limit: int,
    cursor: str | None,
    has_ledger: bool,
    dialect: Dialect,
    scope: Mapping[str, str],
    metadata: dict[str, Any] | None,
) -> Page:
    from agent_bom.api.finding_lifecycle import enriched_finding_payload
    from agent_bom.api.storage.hub_filters import collect_scope_filtered_page, scope_filter_batch_size
    from agent_bom.finding_scope import row_matches_scope

    def fetch(batch_cursor: str | None, batch_limit: int) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]:
        rows, next_cursor = fetch_page(
            tx,
            tenant,
            where=where,
            params=params,
            sort=sort,
            limit=batch_limit,
            offset=0,
            cursor=batch_cursor,
            has_ledger=has_ledger,
            dialect=dialect,
        )
        return [(row, enriched_finding_payload(row)) for row in rows], next_cursor

    rows, next_cursor = collect_scope_filtered_page(
        fetch,
        predicate=lambda payload: row_matches_scope(payload, scope),
        page_limit=limit,
        start_cursor=cursor,
        sort=sort,
        batch_size=scope_filter_batch_size(limit),
        metadata=metadata,
    )
    return rows, None, next_cursor


def _has_pending(tx: SqlSession, tenant: str) -> bool:
    row = tx.execute("SELECT 1 FROM hub_findings_current WHERE tenant_id = ? AND issue_group_id IS NULL LIMIT 1", (tenant,)).fetchone()
    return row is not None


def _kev_group_ids_sql(where_sql: str) -> str:
    """Issue groups holding a KEV occurrence: both legs ride a small partial index."""
    return (
        f"SELECT issue_group_id FROM hub_findings_current WHERE {where_sql} AND kev_direct "  # nosec B608
        f"UNION SELECT issue_group_id FROM hub_findings_current WHERE {where_sql} AND {_KEV_VIA_INTEL}"
    )


class SqlCurrentFindingReads:
    def __init__(self, backend: SqlBackend) -> None:
        self._backend = backend

    def get(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            has_ledger = has_ledger_column(tx, self._backend.dialect)
            row = tx.execute(
                f"SELECT {columns(has_ledger)} FROM hub_findings_current WHERE tenant_id = ? AND canonical_id = ?",  # nosec B608
                (tenant, canonical_id),
            ).fetchone()  # nosec B608
            return hydrate_rows(tx, tenant, [parse_row(row, has_ledger_col=has_ledger)])[0] if row else None

    def lookup(self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None) -> set[str]:
        tenant = require_explicit_tenant_id(tenant_id)
        found: set[str] = set()
        keys = list(dict.fromkeys(canonical_ids))
        with self._backend.transaction(read_only=True) as tx:
            for start in range(0, len(keys), 500):
                batch = keys[start : start + 500]
                predicate = "tenant_id = ? AND canonical_id IN (" + ",".join("?" for _ in batch) + ")"
                params: list[Any] = [tenant, *batch]
                for column, value in [("scan_id", scan_id), ("origin", origin)]:
                    if value is not None:
                        predicate += f" AND {column} = ?"
                        params.append(value)
                rows = tx.execute(f"SELECT canonical_id FROM hub_findings_current WHERE {predicate}", params).fetchall()  # nosec B608
                found.update(str(row[0]) for row in rows)
        return found

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
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
        scope_metadata: dict[str, Any] | None = None,
    ) -> Page:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        tenant = require_explicit_tenant_id(tenant_id)
        normalized = sort if sort in ("ordinal", "cvss", "severity", "effective_reach") else "effective_reach"
        limit = max(0, int(limit))
        with self._backend.transaction(read_only=True) as tx:
            has_ledger = has_ledger_column(tx, self._backend.dialect)
            # The KEV column answers exactly once every row is materialized; a pending
            # row may hold its flag only inside a compressed payload, so walk instead.
            kev_pushed = scope is not None and scope.get("kev") == "true" and not _has_pending(tx, tenant)
            if kev_pushed and scope is not None:
                scope = {key: value for key, value in scope.items() if key != "kev"}
            where, params = filters(tenant, since=since, origin=origin, severity=severity, scan_id=scan_id, status=status, kev=kev_pushed)
            if scope:
                return scoped_page(
                    tx,
                    tenant,
                    where=where,
                    params=params,
                    sort=normalized,
                    limit=limit,
                    cursor=cursor,
                    has_ledger=has_ledger,
                    dialect=self._backend.dialect,
                    scope=scope,
                    metadata=scope_metadata,
                )
            total = None
            if include_total and not cursor:
                row = tx.execute("SELECT COUNT(*) FROM hub_findings_current WHERE " + " AND ".join(where), params).fetchone()  # nosec B608
                total = int(row[0]) if row else 0
            rows, next_cursor = fetch_page(
                tx,
                tenant,
                where=where,
                params=params,
                sort=normalized,
                limit=limit,
                offset=int(offset),
                cursor=cursor,
                has_ledger=has_ledger,
                dialect=self._backend.dialect,
            )
            return [enriched_finding_payload(row) for row in rows], total, next_cursor

    def materialization_pending(self, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            return _has_pending(tx, tenant)

    def kev_count(self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None) -> int:
        tenant = require_explicit_tenant_id(tenant_id)
        where, params = filters(tenant, since=since, origin=origin, severity=None, scan_id=None, status=status)
        where_sql = " AND ".join(where)
        with self._backend.transaction(read_only=True) as tx:
            direct = tx.execute(f"SELECT COUNT(*) FROM hub_findings_current WHERE {where_sql} AND kev_direct", params).fetchone()  # nosec B608
            via_intel = tx.execute(
                f"SELECT COUNT(*) FROM hub_findings_current WHERE {where_sql} AND {_KEV_VIA_INTEL}",  # nosec B608
                (*params, tenant),
            ).fetchone()
        return int(direct[0] if direct else 0) + int(via_intel[0] if via_intel else 0)

    def issue_group_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, int] | None:
        """Exact open issue groups per band, each at its worst occurrence; ``None`` while any row is pending."""
        tenant = require_explicit_tenant_id(tenant_id)
        where, params = filters(tenant, since=since, origin=origin, severity=None, scan_id=None, status=status)
        where_sql = " AND ".join(where)
        counts = empty_severity_histogram()
        with self._backend.transaction(read_only=True) as tx:
            if _has_pending(tx, tenant):
                return None
            rows = tx.execute(
                f"SELECT worst, COUNT(*) FROM (SELECT issue_group_id, MAX({_ISSUE_RANK_SQL}) AS worst "  # nosec B608
                f"FROM hub_findings_current WHERE {where_sql} GROUP BY issue_group_id) groups GROUP BY worst",
                params,
            ).fetchall()
            info = unknown = 0
            for rank, count in rows:
                counts[issue_rank_band(int(rank))] += int(count)
                info += int(count) if int(rank) == 1 else 0
                unknown += int(count) if int(rank) == 0 else 0
            kev = tx.execute(f"SELECT COUNT(*) FROM ({_kev_group_ids_sql(where_sql)}) kev_groups", (*params, *params, tenant)).fetchone()  # nosec B608
        return {**counts, "info": info, "unknown": unknown, "total": sum(counts.values()), "kev": int(kev[0] if kev else 0)}

    def issue_group_lookup(
        self, tenant_id: str, group_ids: Sequence[str], *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, tuple[int, bool]]:
        """Worst rank and KEV state of named groups, so scan rows can merge onto them."""
        tenant = require_explicit_tenant_id(tenant_id)
        where, params = filters(tenant, since=since, origin=origin, severity=None, scan_id=None, status=status)
        where_sql = " AND ".join(where)
        keys = list(dict.fromkeys(group_ids))
        found: dict[str, tuple[int, bool]] = {}
        with self._backend.transaction(read_only=True) as tx:
            for start in range(0, len(keys), 500):
                batch = keys[start : start + 500]
                markers = ",".join("?" for _ in batch)
                in_batch = f"{where_sql} AND issue_group_id IN ({markers})"
                rows = tx.execute(
                    f"SELECT issue_group_id, MAX({_ISSUE_RANK_SQL}) FROM hub_findings_current WHERE {in_batch} GROUP BY issue_group_id",  # nosec B608
                    (*params, *batch),
                ).fetchall()
                kev_rows = tx.execute(_kev_group_ids_sql(in_batch), (*params, *batch, *params, *batch, tenant)).fetchall()
                kev = {str(row[0]) for row in kev_rows}
                found.update((str(row[0]), (int(row[1]), str(row[0]) in kev)) for row in rows)
        return found

    def failing_framework_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, int]:
        """Canonical framework slugs on live critical and high rows, read without a ledger join."""
        from agent_bom.compliance_coverage import normalize_framework_slug

        tenant = require_explicit_tenant_id(tenant_id)
        where, params = filters(tenant, since=since, origin=origin, severity=None, scan_id=None, status=status)
        where_sql = " AND ".join(where)
        with self._backend.transaction(read_only=True) as tx:
            rows = tx.execute(
                f"SELECT frameworks_csv, COUNT(*) FROM hub_findings_current WHERE {where_sql} "  # nosec B608
                "AND LOWER(severity) IN ('critical', 'high') AND frameworks_csv <> '' GROUP BY frameworks_csv",
                params,
            ).fetchall()
        counts: dict[str, int] = {}
        for csv, count in rows:
            for token in str(csv).split(","):
                if token.strip():
                    slug = normalize_framework_slug(token.strip())
                    counts[slug] = counts.get(slug, 0) + int(count)
        return counts

    def coverage_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, dict[str, int]] | None:
        """Exact occurrence counts per coverage lane and for the Vuln / SCA card; ``None`` while pending."""
        tenant = require_explicit_tenant_id(tenant_id)
        where, params = filters(tenant, since=since, origin=origin, severity=None, scan_id=None, status=status)
        where_sql = " AND ".join(where)
        lanes = {domain: empty_severity_histogram() for domain in LENS_BITS}
        cves = {**empty_severity_histogram(), "kev": 0}
        with self._backend.transaction(read_only=True) as tx:
            if _has_pending(tx, tenant):
                return None
            rows = tx.execute(
                f"SELECT lens_mask, severity, COUNT(*) FROM hub_findings_current WHERE {where_sql} GROUP BY lens_mask, severity",  # nosec B608
                params,
            ).fetchall()
            for mask, severity, count in rows:
                band = severity_display_bucket(str(severity or ""))
                for domain, bit in LENS_BITS.items():
                    if int(mask) & bit:
                        lanes[domain][band] += int(count)
                if int(mask) & VULN_CARD_BIT:
                    cves[band] += int(count)
            card = f"{where_sql} AND (lens_mask & {VULN_CARD_BIT}) <> 0"
            direct = tx.execute(f"SELECT COUNT(*) FROM hub_findings_current WHERE {card} AND kev_direct", params).fetchone()  # nosec B608
            via_intel = tx.execute(
                f"SELECT COUNT(*) FROM hub_findings_current WHERE {card} AND {_KEV_VIA_INTEL}",  # nosec B608
                (*params, tenant),
            ).fetchone()
        cves["kev"] = int(direct[0] if direct else 0) + int(via_intel[0] if via_intel else 0)
        return {**lanes, "_cves": cves}


class CurrentFindingAggregates:
    """The exact current-state aggregates both SQL adapters serve the same way."""

    @property
    def _current_reads(self) -> SqlCurrentFindingReads:
        raise NotImplementedError

    def current_kev_count(self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None) -> int:
        # Materialized flag plus the tenant's CVE reference, never keys inside
        # payloads: payloads of 512 bytes or more are compressed at rest.
        return self._current_reads.kev_count(tenant_id, origin=origin, since=since, status=status)

    def current_failing_framework_slug_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, int]:
        return self._current_reads.failing_framework_counts(tenant_id, origin=origin, since=since, status=status)

    def current_materialization_pending(self, tenant_id: str) -> bool:
        return self._current_reads.materialization_pending(tenant_id)

    def current_issue_group_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, int] | None:
        return self._current_reads.issue_group_counts(tenant_id, origin=origin, since=since, status=status)

    def current_issue_group_lookup(
        self, tenant_id: str, group_ids: Sequence[str], *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, tuple[int, bool]]:
        return self._current_reads.issue_group_lookup(tenant_id, group_ids, origin=origin, since=since, status=status)

    def current_coverage_counts(
        self, tenant_id: str, *, origin: str | None = None, since: str | None = None, status: str | None = None
    ) -> dict[str, dict[str, int]] | None:
        return self._current_reads.coverage_counts(tenant_id, origin=origin, since=since, status=status)
