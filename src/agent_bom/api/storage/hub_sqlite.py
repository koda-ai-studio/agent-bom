"""Compliance hub sqlite implementation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score
from agent_bom.api.storage.finding_current_reads import SqlCurrentFindingReads
from agent_bom.api.storage.finding_current_writes import current_ledger_candidates, reconcile_current, write_current_batch
from agent_bom.api.storage.finding_ingest_state import LedgerIngestState, read_ingest_state, write_ingest_state
from agent_bom.api.storage.finding_ledger_writes import write_ledger_batch
from agent_bom.api.storage.finding_reads import SqlFindingReads
from agent_bom.api.storage.finding_write_session import finding_write_session
from agent_bom.api.storage.hub_contract import FindingCursorPage, FindingPage
from agent_bom.api.storage.hub_filters import _kev_json_cond_sqlite, _redact_findings, status_sql_predicate
from agent_bom.api.storage.hub_schema import SQLiteHubSchema, _bump_overview_revision_sqlite
from agent_bom.api.storage.sql import SQLiteBackend
from agent_bom.core.tenancy import require_explicit_tenant_id


class SQLiteComplianceHubStore(SQLiteHubSchema):
    """SQLite-backed hub store for single-node persistence.

    NOT safe for multi-replica API deployments: SQLite's WAL is local to
    the file. Use ``PostgresComplianceHubStore`` when more than one API
    pod must share findings.
    """

    @property
    def _current_reads(self) -> SqlCurrentFindingReads:
        return SqlCurrentFindingReads(SQLiteBackend(self._db_path, connection_factory=lambda: self._conn))

    @property
    def _ledger_reads(self) -> SqlFindingReads:
        return SqlFindingReads(SQLiteBackend(self._db_path, connection_factory=lambda: self._conn))

    def _invalidate_ingest_caches(self, tenant_id: str) -> None:
        from agent_bom.api import hub_overview_cache
        from agent_bom.api.findings_count_cache import invalidate_tenant

        invalidate_tenant(tenant_id)
        hub_overview_cache.invalidate_tenant(tenant_id)

    def overview_evidence_revision(self, tenant_id: str) -> int:
        return self._ledger_reads.overview_evidence_revision(tenant_id)

    def _ledger_insert_no_commit(self, tenant_id: str, findings: list[dict[str, Any]]) -> tuple[int, int]:
        tx = finding_write_session(self._conn, "sqlite", tenant_id)
        state = read_ingest_state(tx, tenant_id)
        new_rows, num_rows = write_ledger_batch(tx, "sqlite", tenant_id, findings, next_ordinal=state.next_ordinal)
        total = state.finding_count + new_rows
        # Allocate for input offsets, including skipped values; valid rows after
        # malformed entries must never overlap the following batch's allocation.
        write_ingest_state(tx, tenant_id, LedgerIngestState(total, state.next_ordinal + len(findings)))
        return total, num_rows

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._conn:
            total, num_rows = self._ledger_insert_no_commit(tenant_id, findings)
            if num_rows:
                _bump_overview_revision_sqlite(self._conn, tenant_id)
        if num_rows:
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
        """Ledger append + current upsert (+ reconcile) in ONE transaction.

        ``add`` / ``upsert_current_batch`` / ``reconcile_current_absent`` each
        committed independently, so a crash between the ledger commit and the
        current-state upsert left ``tenant_total`` inflated while the findings
        never appeared in any list. Threading all three writes through a single
        ``with conn`` block (commit on success, rollback on failure) makes a
        mid-batch failure roll BOTH back, mirroring the Postgres seam. Durable
        ordinal/count state commits or rolls back with the ledger. Returns
        ``(new_total, reconciled)``.
        """
        tenant_id = require_explicit_tenant_id(tenant_id)
        conn = self._conn
        with conn:  # sqlite3 connection: commit on success, rollback on exception
            tx = finding_write_session(conn, "sqlite", tenant_id)
            candidates = current_ledger_candidates(tx, tenant_id, findings, observed_at=observed_at, batch_id=batch_id, source=source)
            new_total, _ = self._ledger_insert_no_commit(tenant_id, candidates)
            self._upsert_current_no_commit(
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            reconciled = 0
            if reconcile_absent:
                reconciled = self._reconcile_current_absent_no_commit(
                    tenant_id,
                    present_canonical_ids=present_canonical_ids,
                    observed_at=observed_at,
                    scope_source=source,
                )
            _bump_overview_revision_sqlite(conn, tenant_id)
        self._invalidate_ingest_caches(tenant_id)
        return new_total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        return self._ledger_reads.list(tenant_id)

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
        return self._ledger_reads.list_page(
            tenant_id, limit=limit, offset=offset, sort=sort, severity=severity, scan_id=scan_id, origin=origin, include_total=include_total
        )

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` column (populated on ingest and
        # backed by ``idx_hub_findings_tenant_severity_ci``) instead of an
        # unindexed per-row ``json_extract(payload, '$.severity')`` decode (#3963).
        return self._ledger_reads.severity_breakdown(tenant_id)

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` column on the current-state
        # table, applying the SAME tenant/since/origin/status predicates
        # ``list_current_page`` counts on, so the exec headline reconciles
        # exactly with the ``/v1/findings`` drill-down (#3961/#4009). The
        # lifecycle ``status`` filter keeps resolved rows out of the headline.
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("last_seen >= ?")
            params.append(since)
        if origin is not None:
            where.append("origin = ?")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status)
        if status_sql:
            where.append(status_sql)
            params.extend(status_params)
        where_sql = " AND ".join(where)
        rows = self._conn.execute(
            f"""
            SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*)
            FROM hub_findings_current
            WHERE {where_sql}
            GROUP BY sev
            """,  # nosec B608
            params,
        ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for sev, count in rows:
            key = str(sev or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> int:
        # Same tenant/since/origin/status predicates as ``current_severity_breakdown``.
        # The KEV flag is not a current-state column (the overlay keeps only
        # sort/filter scalars), so resolve it from the current payload, the joined
        # ledger payload, and the CVE-intel reference — the exact places the drill
        # hydrates it from — so the exec KEV count reconciles with the drill.
        where = ["c.tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("c.last_seen >= ?")
            params.append(since)
        if origin is not None:
            where.append("c.origin = ?")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status)
        if status_sql:
            where.append(status_sql.replace("status", "c.status", 1))
            params.extend(status_params)
        where_sql = " AND ".join(where)
        kev_cond = " OR ".join(_kev_json_cond_sqlite(col) for col in ("c.payload", "l.payload", "i.payload"))
        row = self._conn.execute(
            f"""
            SELECT COUNT(*)
            FROM hub_findings_current c
            LEFT JOIN compliance_hub_findings l
                ON l.tenant_id = c.tenant_id AND l.finding_id = c.ledger_finding_id
            LEFT JOIN hub_cve_intel i
                ON i.tenant_id = c.tenant_id AND i.cve_id = json_extract(l.payload, '$.intel_ref')
            WHERE {where_sql} AND ({kev_cond})
            """,  # nosec B608
            params,
        ).fetchone()
        return int((row[0] if row else 0) or 0)

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        # Split + aggregate the denormalised CSV IN SQL via a recursive CTE so
        # the query returns O(distinct slugs) rows, never the full tenant ledger
        # pulled into Python (#3963). The handful of raw tokens are then folded
        # to canonical slugs (alias/underscore normalisation) in Python.
        rows = self._conn.execute(
            """
            WITH RECURSIVE split(rest, token) AS (
                SELECT applicable_frameworks_csv || ',', ''
                  FROM compliance_hub_findings
                 WHERE tenant_id = ? AND applicable_frameworks_csv <> ''
                UNION ALL
                SELECT substr(rest, instr(rest, ',') + 1),
                       substr(rest, 1, instr(rest, ',') - 1)
                  FROM split
                 WHERE rest <> ''
            )
            SELECT TRIM(token) AS slug, COUNT(*) AS n
              FROM split
             WHERE TRIM(token) <> ''
             GROUP BY TRIM(token)
            """,
            (tenant_id,),
        ).fetchall()
        counts: dict[str, int] = {}
        for slug, n in rows:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + int(n)
        return counts

    def current_failing_framework_slug_counts(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        where = ["c.tenant_id = ?", "LOWER(c.severity) IN ('critical', 'high')"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("c.last_seen >= ?")
            params.append(since)
        if origin is not None:
            where.append("c.origin = ?")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status)
        if status_sql:
            where.append(status_sql.replace("status", "c.status", 1))
            params.extend(status_params)
        rows = self._conn.execute(
            f"""
            WITH RECURSIVE selected(csv) AS (
                SELECT l.applicable_frameworks_csv
                FROM hub_findings_current c
                JOIN compliance_hub_findings l
                  ON l.tenant_id = c.tenant_id AND l.finding_id = c.ledger_finding_id
                WHERE {" AND ".join(where)} AND l.applicable_frameworks_csv <> ''
            ), split(rest, token) AS (
                SELECT csv || ',', '' FROM selected
                UNION ALL
                SELECT substr(rest, instr(rest, ',') + 1),
                       substr(rest, 1, instr(rest, ',') - 1)
                FROM split WHERE rest <> ''
            )
            SELECT TRIM(token), COUNT(*) FROM split
            WHERE TRIM(token) <> '' GROUP BY TRIM(token)
            """,  # nosec B608
            params,
        ).fetchall()
        counts: dict[str, int] = {}
        for slug, count in rows:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + int(count)
        return counts

    def count(self, tenant_id: str) -> int:
        return self._ledger_reads.count(tenant_id)

    def clear(self, tenant_id: str) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._conn:
            tx = finding_write_session(self._conn, "sqlite", tenant_id)
            state = read_ingest_state(tx, tenant_id)
            cur = self._conn.execute(
                "DELETE FROM compliance_hub_findings WHERE tenant_id = ?",
                (tenant_id,),
            )
            self._conn.execute("DELETE FROM hub_findings_current WHERE tenant_id = ?", (tenant_id,))
            self._conn.execute("DELETE FROM hub_findings_current_observations WHERE tenant_id = ?", (tenant_id,))
            write_ingest_state(tx, tenant_id, LedgerIngestState(0, state.next_ordinal))
            _bump_overview_revision_sqlite(self._conn, tenant_id)
        removed = cur.rowcount or 0
        if removed:
            from agent_bom.api import hub_overview_cache
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
            hub_overview_cache.invalidate_tenant(tenant_id)
        return removed

    def _upsert_current_no_commit(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        tx = finding_write_session(self._conn, "sqlite", tenant_id)
        write_current_batch(
            tx,
            "sqlite",
            tenant_id,
            _redact_findings(findings),
            observed_at=observed_at,
            batch_id=batch_id,
            source=source,
            has_ledger=self._ensure_current_has_ledger_col(),
        )

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
        with self._conn:
            self._upsert_current_no_commit(
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            if findings:
                _bump_overview_revision_sqlite(self._conn, tenant_id)
        if findings:
            self._invalidate_ingest_caches(tenant_id)

    def lookup_current_ids(
        self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None
    ) -> set[str]:
        return self._current_reads.lookup(tenant_id, canonical_ids, scan_id=scan_id, origin=origin)

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        return self._current_reads.get(tenant_id, canonical_id)

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
        return self._current_reads.list_page(
            tenant_id,
            limit=limit,
            offset=offset,
            sort=sort,
            severity=severity,
            scan_id=scan_id,
            origin=origin,
            include_total=include_total,
            cursor=cursor,
            since=since,
            scope=scope,
            status=status,
            scope_metadata=scope_metadata,
        )

    def _reconcile_current_absent_no_commit(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        tx = finding_write_session(self._conn, "sqlite", tenant_id)
        return reconcile_current(
            tx, "sqlite", tenant_id, present_canonical_ids=present_canonical_ids, observed_at=observed_at, scope_source=scope_source
        )

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with self._conn:
            total = self._reconcile_current_absent_no_commit(
                tenant_id,
                present_canonical_ids=present_canonical_ids,
                observed_at=observed_at,
                scope_source=scope_source,
            )
            if total:
                _bump_overview_revision_sqlite(self._conn, tenant_id)
        if total:
            self._invalidate_ingest_caches(tenant_id)
        return total
