"""Compliance hub schema implementation."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from typing import Any

from agent_bom.api.finding_rank import compute_effective_reach_score as compute_effective_reach_score
from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    hydrate_current_payload,
)
from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.hub_reference_store import (
    ensure_sqlite_reference_tables,
    hydrate_finding_payloads_sqlite,
)
from agent_bom.api.storage.campaign_revisions import initialize_sqlite_campaign_evidence
from agent_bom.api.storage.finding_ingest_state import ensure_sqlite_ingest_state
from agent_bom.api.storage.hub_contract import _LEDGER_ORDINAL_SENTINEL, _SCHEMA_KEY, _SCHEMA_VERSION
from agent_bom.api.storage.sqlite_connection import open_wal_connection
from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.storage.factory import validate_sqlite_path


def _fetch_ledger_payloads_sqlite(
    conn: sqlite3.Connection,
    tenant_id: str,
    finding_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    if not finding_ids:
        return {}
    placeholders = ",".join("?" * len(finding_ids))
    rows = conn.execute(
        f"""
        SELECT finding_id, payload
        FROM compliance_hub_findings
        WHERE tenant_id = ? AND finding_id IN ({placeholders})
        """,  # nosec B608
        (tenant_id, *finding_ids),
    ).fetchall()
    if not rows:
        return {}
    ordered_ids = [str(row[0]) for row in rows]
    payloads = [decode_hub_payload(row[1]) for row in rows]
    hydrated = hydrate_finding_payloads_sqlite(conn, tenant_id, payloads)
    return dict(zip(ordered_ids, hydrated))


def _sqlite_current_row_from_db(row: tuple[Any, ...], *, has_ledger_col: bool) -> dict[str, Any]:
    current_row = {
        "canonical_id": row[0],
        "first_seen": row[1],
        "last_seen": row[2],
        "status": row[3],
        "severity": row[4],
        "severity_rank": row[5],
        "cvss_score": row[6],
        "effective_reach_score": row[7],
        "scan_count": row[8],
        "resolved_at": row[9],
        "reopened_at": row[10],
        "updated_at": row[11],
        "payload": decode_hub_payload(row[12]),
    }
    if has_ledger_col:
        current_row["ledger_finding_id"] = row[13]
        if len(row) > 14:
            current_row["ledger_ordinal"] = int(row[14])
    return current_row


def _hydrate_sqlite_current_rows(
    conn: sqlite3.Connection,
    tenant_id: str,
    current_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ledger_map = batch_ledger_payloads(
        lambda ids: _fetch_ledger_payloads_sqlite(conn, tenant_id, ids),
        [str(row.get("ledger_finding_id") or "") for row in current_rows],
    )
    hydrated: list[dict[str, Any]] = []
    for row in current_rows:
        hydrated_row = dict(row)
        hydrated_row["payload"] = hydrate_current_payload(row, ledger_payloads=ledger_map)
        hydrated.append(hydrated_row)
    return hydrated


def _hub_findings_current_has_ledger_col(conn: sqlite3.Connection) -> bool:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    return "ledger_finding_id" in cols


def _migrate_current_ledger_ref_sqlite(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "ledger_finding_id" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN ledger_finding_id TEXT")


def _migrate_current_ledger_ordinal_sqlite(conn: sqlite3.Connection) -> None:
    """Materialise the ledger ingest ``ordinal`` onto ``hub_findings_current``.

    ``sort=ordinal`` used to resolve ingest order with a per-row correlated
    subquery against the ledger (full scan + filesort at scale, #3984). This
    promotes it to a stored column so the sort rides
    ``idx_hub_findings_current_tenant_ordinal`` as an ordered range scan.

    The guarded ALTER seeds every pre-existing row with the sort sentinel
    (``MAX(bigint)``), then the one-shot backfill resolves the real ordinal for
    rows that carry a ledger pointer — matching the old
    ``COALESCE(subquery, 9223372036854775807)`` value exactly. Idempotent: the
    ALTER+backfill only run while the column is absent, and empty tables update
    zero rows. Requires ``ledger_finding_id`` to already exist.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "ledger_ordinal" not in cols:
        conn.execute(f"ALTER TABLE hub_findings_current ADD COLUMN ledger_ordinal INTEGER NOT NULL DEFAULT {_LEDGER_ORDINAL_SENTINEL}")
        conn.execute(
            """
            UPDATE hub_findings_current SET ledger_ordinal = COALESCE(
                (
                    SELECT f.ordinal
                    FROM compliance_hub_findings f
                    WHERE f.tenant_id = hub_findings_current.tenant_id
                      AND f.finding_id = hub_findings_current.ledger_finding_id
                    LIMIT 1
                ),
                ?
            )
            WHERE ledger_finding_id IS NOT NULL AND ledger_finding_id != ''
            """,
            (_LEDGER_ORDINAL_SENTINEL,),
        )


def _migrate_current_origin_col_sqlite(conn: sqlite3.Connection) -> None:
    """Promote ``origin`` to a real indexed column on ``hub_findings_current``.

    Filtering ``origin`` via ``json_extract(payload, '$.origin')`` forces a
    full-table scan on the exact ``COUNT(*)`` (#3641). Backfilling a materialised
    column from the stored overlay lets the count ride the
    ``(tenant_id, origin, …)`` index prefix. Idempotent: the guarded ALTER only
    runs once and the backfill only touches empty ``origin`` cells.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "origin" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE hub_findings_current SET origin = COALESCE(json_extract(payload, '$.origin'), '') WHERE origin = ''")


def _migrate_current_scan_id_col_sqlite(conn: sqlite3.Connection) -> None:
    """Promote ``scan_id`` to a real indexed column on ``hub_findings_current``.

    The default ``/v1/findings`` (current-state) reach read filtered ``scan_id``
    via ``json_extract(payload, '$.batch_id'/'$.scan_id')`` per row — a full-table
    scan of the tenant, paid twice (COUNT + page). This mirrors the ledger fix
    (#3641/#3913): backfill a materialised column so the filter rides an index.

    The materialised value matches the canonical in-memory filter
    (``batch_id or scan_id``): ``batch_id`` takes precedence and ``scan_id`` is
    the fallback, so pre-migration rows resolve to the exact same key the old
    per-row json_extract compared against. Idempotent: the guarded ALTER runs
    once and the backfill only touches empty cells.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "scan_id" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "UPDATE hub_findings_current SET scan_id = "
            "COALESCE(NULLIF(json_extract(payload, '$.batch_id'), ''), json_extract(payload, '$.scan_id'), '') "
            "WHERE scan_id = ''"
        )


def _ensure_current_scale_indexes_sqlite(conn: sqlite3.Connection) -> None:
    """Partial indexes backing the current-state scan_id + severity filters.

    Both are ``WHERE <col> != ''`` partial indexes: the common rows (no scan_id,
    or an empty severity) stay OUT of the index so an all-empty
    ``(tenant_id, col)`` index cannot shadow the default reach read as a
    perfect tenant-equality candidate and force a filesort. Real filters always
    query a non-empty value, so the partial index still serves them (mirrors the
    ledger treatment in ``_ensure_scale_indexes``).
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_scan ON hub_findings_current(tenant_id, scan_id) WHERE scan_id != ''"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_ci "
        "ON hub_findings_current(tenant_id, LOWER(severity)) WHERE severity != ''"
    )


def _ensure_current_lifecycle_sqlite(conn: sqlite3.Connection) -> None:
    from agent_bom.api.finding_lifecycle import (
        _CURRENT_LIFECYCLE_SORT_INDEXES_SQLITE,
        _CURRENT_LIFECYCLE_SQLITE_DDL,
    )

    # executescript commits an open transaction; keep schema upgrades atomic.
    for statement in _CURRENT_LIFECYCLE_SQLITE_DDL.split(";"):
        if statement.strip():
            conn.execute(statement)
    # Backfill the origin column before the sort indexes so the composite
    # ``(tenant_id, origin, cvss_score DESC, …)`` index can build on pre-existing
    # tables that predate the column.
    _migrate_current_origin_col_sqlite(conn)
    # Materialise scan_id before its index so the partial index can build on
    # tables that predate the column (the default /v1/findings scan filter).
    _migrate_current_scan_id_col_sqlite(conn)
    # Materialise the ledger pointer + its ingest ordinal before the sort
    # indexes so the ``(tenant_id, ledger_ordinal, …)`` index can build on
    # pre-existing tables that predate those columns (#3984).
    _migrate_current_ledger_ref_sqlite(conn)
    _migrate_current_ledger_ordinal_sqlite(conn)
    for statement in _CURRENT_LIFECYCLE_SORT_INDEXES_SQLITE.split(";"):
        if statement.strip():
            conn.execute(statement)
    _ensure_current_scale_indexes_sqlite(conn)
    _migrate_lifecycle_observations_l2_sqlite(conn)
    conn.execute("UPDATE hub_findings_current SET cvss_score = 0 WHERE cvss_score IS NULL")


def _migrate_lifecycle_observations_l2_sqlite(conn: sqlite3.Connection) -> None:
    """Upgrade L1 observation rows (PK on observed_at) to L2 (PK on scan_id)."""
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hub_findings_current_observations'").fetchall()
    if not rows:
        return
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current_observations)").fetchall()}
    if "scan_id" in cols:
        return
    conn.execute("ALTER TABLE hub_findings_current_observations RENAME TO hub_findings_current_observations_l1")
    conn.execute(
        """
        CREATE TABLE hub_findings_current_observations (
            tenant_id TEXT NOT NULL,
            canonical_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, canonical_id, scan_id)
        )
        """
    )
    conn.execute(
        """
        INSERT INTO hub_findings_current_observations (tenant_id, canonical_id, scan_id, observed_at)
        SELECT tenant_id, canonical_id, observed_at, observed_at
        FROM hub_findings_current_observations_l1
        """
    )
    conn.execute("DROP TABLE hub_findings_current_observations_l1")


def _frameworks_csv(payload: dict[str, Any]) -> str:
    """Denormalise the framework slug list into a sortable CSV column."""
    slugs = payload.get("applicable_frameworks") or []
    if not isinstance(slugs, list):
        return ""
    return ",".join(str(s) for s in slugs if s)


def _now_utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_overview_revision_sqlite(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS hub_overview_revisions (
        tenant_id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0
        )"""
    )

    initialize_sqlite_campaign_evidence(conn)


def _bump_overview_revision_sqlite(conn: sqlite3.Connection, tenant_id: str) -> None:
    conn.execute(
        """INSERT INTO hub_overview_revisions (tenant_id, revision) VALUES (?, 1)
        ON CONFLICT(tenant_id) DO UPDATE SET revision = revision + 1""",
        (tenant_id,),
    )


def resolve_current_ledger_ordinal_sqlite(
    conn: sqlite3.Connection,
    tenant_id: str,
    ledger_finding_id: str,
) -> int:
    """Return the ledger ingest ``ordinal`` for a current-state row's pointer.

    A point lookup on the ledger primary key ``(tenant_id, finding_id)`` — the
    ledger row is always written (``add``) before the current batch upsert, so
    the ordinal is present. Missing pointers fall back to the sort sentinel.
    """
    if not ledger_finding_id:
        return _LEDGER_ORDINAL_SENTINEL
    row = conn.execute(
        "SELECT ordinal FROM compliance_hub_findings WHERE tenant_id = ? AND finding_id = ?",
        (tenant_id, ledger_finding_id),
    ).fetchone()
    return int(row[0]) if row else _LEDGER_ORDINAL_SENTINEL


class SQLiteHubSchema:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = validate_sqlite_path(db_path)
        self._local = threading.local()
        self._current_has_ledger_col: bool | None = None
        self._init_db()

    def _ensure_current_has_ledger_col(self) -> bool:
        if self._current_has_ledger_col is None:
            self._current_has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        return self._current_has_ledger_col

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = open_wal_connection(self._db_path, normal_sync=True)
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            ensure_sqlite_schema_version(self._conn, _SCHEMA_KEY, _SCHEMA_VERSION)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_hub_findings (
                    tenant_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    effective_reach_score REAL NOT NULL DEFAULT 0,
                    origin TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT '',
                    severity_rank INTEGER NOT NULL DEFAULT 0,
                    cvss_score REAL NOT NULL DEFAULT 0,
                    scan_id TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, finding_id)
                )
                """
            )
            self._migrate_columns()
            self._migrate_primary_key()
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
            self._ensure_scale_indexes()
            _ensure_current_lifecycle_sqlite(self._conn)
            _ensure_overview_revision_sqlite(self._conn)
            ensure_sqlite_reference_tables(self._conn)
            ensure_sqlite_ingest_state(self._conn)

    def _migrate_columns(self) -> None:
        """Add PR1 read-scale columns to pre-existing tables (idempotent)."""
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(compliance_hub_findings)").fetchall()}
        if "effective_reach_score" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN effective_reach_score REAL NOT NULL DEFAULT 0")
        if "origin" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
            # Backfill origin from the stored payload so pre-migration rows
            # remain filterable without a full rewrite on the read path.
            self._conn.execute(
                "UPDATE compliance_hub_findings SET origin = COALESCE(json_extract(payload, '$.origin'), '') WHERE origin = ''"
            )
        # Materialise severity/cvss sort keys so the filtered severity/cvss
        # sorts ride a composite index instead of a json_extract filesort
        # (#3192). Backfill extracts from the stored payload for legacy rows.
        if "severity" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN severity TEXT NOT NULL DEFAULT ''")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET severity = COALESCE(json_extract(payload, '$.severity'), '') WHERE severity = ''"
            )
        if "severity_rank" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN severity_rank INTEGER NOT NULL DEFAULT 0")
            self._conn.execute(
                # Mirror severity_policy_rank() so backfilled ranks match new
                # writes: info==low==1, none==0, everything unknown==-1 (#3192).
                "UPDATE compliance_hub_findings SET severity_rank = CASE "
                "LOWER(COALESCE(json_extract(payload, '$.severity'), '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "WHEN 'info' THEN 1 WHEN 'informational' THEN 1 WHEN 'none' THEN 0 "
                "ELSE -1 END WHERE severity_rank = 0"
            )
        if "cvss_score" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN cvss_score REAL NOT NULL DEFAULT 0")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET cvss_score = "
                "CAST(COALESCE(json_extract(payload, '$.cvss_score'), 0) AS REAL) WHERE cvss_score = 0"
            )
        # Materialise scan_id so the scan filter rides an index instead of a
        # per-row json_extract full scan of the tenant's findings. Backfill from
        # the stored payload for legacy rows.
        if "scan_id" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET scan_id = COALESCE(NULLIF(json_extract(payload, '$.batch_id'), ''), "
                "json_extract(payload, '$.scan_id'), '') WHERE scan_id = ''"
            )

    def _migrate_primary_key(self) -> None:
        """Collapse the primary key to ``(tenant_id, finding_id)`` (idempotent).

        Pre-idempotency tables keyed on ``(tenant_id, finding_id, ordinal)`` so
        every resend of the same finding minted a new row. SQLite cannot ALTER a
        primary key in place, so we rebuild: dedup existing duplicates keeping
        the lowest ordinal (the original ingest), then swap in the new-schema
        table. A no-op when the table already carries the collapsed key.
        """
        pk_cols = [row[1] for row in self._conn.execute("PRAGMA table_info(compliance_hub_findings)").fetchall() if row[5]]
        if "ordinal" not in pk_cols:
            return  # already migrated to (tenant_id, finding_id)

        self._conn.execute(
            """
            CREATE TABLE compliance_hub_findings_v2 (
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                effective_reach_score REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                severity_rank INTEGER NOT NULL DEFAULT 0,
                cvss_score REAL NOT NULL DEFAULT 0,
                scan_id TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, finding_id)
            )
            """
        )
        # Keep the lowest-ordinal row for each (tenant_id, finding_id) so the
        # rebuild is deterministic and preserves the original ingest order.
        self._conn.execute(
            """
            INSERT INTO compliance_hub_findings_v2
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload,
                 ordinal, effective_reach_score, origin, severity, severity_rank, cvss_score, scan_id)
            SELECT f.tenant_id, f.finding_id, f.ingested_at, f.source, f.applicable_frameworks_csv,
                   f.payload, f.ordinal, f.effective_reach_score, f.origin, f.severity, f.severity_rank, f.cvss_score, f.scan_id
            FROM compliance_hub_findings f
            WHERE f.ordinal = (
                SELECT MIN(s.ordinal) FROM compliance_hub_findings s
                WHERE s.tenant_id = f.tenant_id AND s.finding_id = f.finding_id
            )
            """
        )
        self._conn.execute("DROP TABLE compliance_hub_findings")
        self._conn.execute("ALTER TABLE compliance_hub_findings_v2 RENAME TO compliance_hub_findings")

    def _ensure_scale_indexes(self) -> None:
        """Install origin-aware read indexes, replacing the pre-origin index.

        ``CREATE INDEX IF NOT EXISTS`` does not update an existing index with
        the same name, so older SQLite DBs would silently keep
        ``(tenant_id, effective_reach_score, ordinal)`` and scan every tenant
        row for ``origin='bulk_ingest'``. Drop/recreate keeps the migration
        deterministic and idempotent.
        """
        self._conn.execute("DROP INDEX IF EXISTS idx_hub_findings_tenant_reach")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_reach "
            "ON compliance_hub_findings(tenant_id, origin, effective_reach_score DESC, ordinal)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin ON compliance_hub_findings(tenant_id, origin)")
        # Back the filtered severity/cvss sorts with ordered composite indexes
        # so ORDER BY rides an index range scan (no temp B-tree filesort) — the
        # numeric severity_rank keeps critical>high>medium>low ordering (#3192).
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity "
            "ON compliance_hub_findings(tenant_id, origin, severity_rank DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_cvss "
            "ON compliance_hub_findings(tenant_id, origin, cvss_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity_cvss "
            "ON compliance_hub_findings(tenant_id, origin, severity_rank, cvss_score DESC, ordinal)"
        )
        # Non-origin covering sort indexes so the *unfiltered* default reads
        # (``WHERE tenant_id=? ORDER BY <col> DESC, ordinal``) ride an ordered
        # index range scan + LIMIT instead of a temp-B-tree filesort — the
        # origin-scoped indexes above cannot serve them because ``origin`` is an
        # unconstrained middle column (#4049). Distinct names + IF NOT EXISTS so
        # steady-state startup is a no-op (no rebuild); the origin-scoped indexes
        # are kept for the filtered reads that still need origin equality.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_reach_all "
            "ON compliance_hub_findings(tenant_id, effective_reach_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_cvss_all ON compliance_hub_findings(tenant_id, cvss_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_all "
            "ON compliance_hub_findings(tenant_id, severity_rank DESC, ordinal)"
        )
        # Back the scan_id filter with an index (was a per-row json_extract scan).
        # PARTIAL on scan_id != '' so the common no-scan_id rows stay OUT of the
        # index — otherwise an all-empty (tenant_id, scan_id) index looks like a
        # perfect tenant-equality candidate and the planner grabs it for the
        # default reach read, forcing a filesort. Real filters always query a
        # non-empty scan_id, so the partial index still serves them.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_scan ON compliance_hub_findings(tenant_id, scan_id) WHERE scan_id != ''"
        )
        # Expression index so the case-insensitive severity equality filter
        # (LOWER(severity) = ?) is sargable. Partial on severity != '' for the
        # same planner-shadowing reason as the scan index above.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_ci "
            "ON compliance_hub_findings(tenant_id, LOWER(severity)) WHERE severity != ''"
        )
