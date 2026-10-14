"""Persistent graph storage — SQLite-backed unified graph with temporal diffs.

Each scan produces an immutable snapshot of nodes and edges.  The same
node ID can appear in multiple scans — the (id, scan_id, tenant_id) PK
preserves per-scan history so ``load_graph(scan_id=...)`` and
``diff_snapshots(...)`` are always correct.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Iterable, Mapping, Sequence

from agent_bom.db.graph_bootstrap import backfill_edge_metadata
from agent_bom.db.graph_revision import ensure_sqlite_revisions
from agent_bom.db.graph_store_correlation import _correlation_run_from_row as _correlation_run_from_row
from agent_bom.db.graph_store_correlation import claim_correlation_run_execution as claim_correlation_run_execution
from agent_bom.db.graph_store_correlation import count_active_correlation_runs as count_active_correlation_runs
from agent_bom.db.graph_store_correlation import create_correlation_run as create_correlation_run
from agent_bom.db.graph_store_correlation import get_correlation_run as get_correlation_run
from agent_bom.db.graph_store_correlation import get_correlation_run_by_idempotency_key as get_correlation_run_by_idempotency_key
from agent_bom.db.graph_store_correlation import heartbeat_correlation_run_execution as heartbeat_correlation_run_execution
from agent_bom.db.graph_store_correlation import list_correlation_runs as list_correlation_runs
from agent_bom.db.graph_store_correlation import update_correlation_run as update_correlation_run
from agent_bom.db.graph_store_history import _diff_summary_counts as _diff_summary_counts
from agent_bom.db.graph_store_history import _edge_change_fingerprint as _edge_change_fingerprint
from agent_bom.db.graph_store_history import _edge_history_row as _edge_history_row
from agent_bom.db.graph_store_history import active_edges_at as active_edges_at
from agent_bom.db.graph_store_history import changed_edges_between_scans as changed_edges_between_scans
from agent_bom.db.graph_store_history import diff_snapshots as diff_snapshots
from agent_bom.db.graph_store_history import list_snapshots as list_snapshots
from agent_bom.db.graph_store_history import snapshots_by_ids as snapshots_by_ids
from agent_bom.db.graph_store_schema import _CREATE_TABLES as _CREATE_TABLES
from agent_bom.db.graph_store_schema import _DEFAULT_GRAPH_RETENTION_DAYS as _DEFAULT_GRAPH_RETENTION_DAYS
from agent_bom.db.graph_store_schema import _DEFAULT_GRAPH_WRITE_BATCH_SIZE as _DEFAULT_GRAPH_WRITE_BATCH_SIZE
from agent_bom.db.graph_store_schema import _FINDING_ENTITY_TYPES as _FINDING_ENTITY_TYPES
from agent_bom.db.graph_store_schema import _GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS as _GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS
from agent_bom.db.graph_store_schema import _GRAPH_EVIDENCE_INCLUDED_TABLES as _GRAPH_EVIDENCE_INCLUDED_TABLES
from agent_bom.db.graph_store_schema import _GRAPH_PURGEABLE_TABLES as _GRAPH_PURGEABLE_TABLES
from agent_bom.db.graph_store_schema import _GRAPH_SCHEMA_VERSION as _GRAPH_SCHEMA_VERSION
from agent_bom.db.graph_store_schema import _GRAPH_TENANT_TABLE_KEYS as _GRAPH_TENANT_TABLE_KEYS
from agent_bom.db.graph_store_schema import ATTACK_PATH_ORDER, ATTACK_PATH_SELECT, attack_path_from_row, upgrade_attack_path_identity
from agent_bom.db.graph_store_schema import DEFAULT_GRAPH_TENANT_ID as DEFAULT_GRAPH_TENANT_ID
from agent_bom.db.graph_store_schema import GRAPH_SNAPSHOT_KINDS as GRAPH_SNAPSHOT_KINDS
from agent_bom.db.graph_store_schema import _batched_rows as _batched_rows
from agent_bom.db.graph_store_schema import _digest_payload as _digest_payload
from agent_bom.db.graph_store_schema import _executemany_batched as _executemany_batched
from agent_bom.db.graph_store_schema import _graph_retention_days as _graph_retention_days
from agent_bom.db.graph_store_schema import _parse_iso_timestamp as _parse_iso_timestamp
from agent_bom.db.graph_store_schema import _read_purge_state as _read_purge_state
from agent_bom.db.graph_store_schema import _record_purge_state as _record_purge_state
from agent_bom.db.graph_store_schema import _table_exists as _table_exists
from agent_bom.db.graph_store_schema import normalize_graph_tenant_id as normalize_graph_tenant_id
from agent_bom.db.graph_store_schema import normalize_snapshot_kind as normalize_snapshot_kind
from agent_bom.db.graph_store_snapshots import _edge_from_snapshot_row as _edge_from_snapshot_row
from agent_bom.db.graph_store_snapshots import _node_from_snapshot_row as _node_from_snapshot_row
from agent_bom.db.graph_store_snapshots import _resolve_snapshot as _resolve_snapshot
from agent_bom.db.graph_store_snapshots import iter_graph_edges as iter_graph_edges
from agent_bom.db.graph_store_snapshots import iter_graph_nodes as iter_graph_nodes
from agent_bom.db.graph_store_snapshots import latest_snapshot_id as latest_snapshot_id
from agent_bom.db.graph_store_snapshots import load_rollup_graph as load_rollup_graph
from agent_bom.db.graph_store_snapshots import previous_snapshot_id as previous_snapshot_id
from agent_bom.db.graph_store_snapshots import prior_delta_digest as prior_delta_digest
from agent_bom.db.graph_store_write import (
    _carry_forward_edge_continuity,
    _check_snapshot_writable,
    _clear_snapshot_rows,
    _complete_correlation_run_atomically,
    _SnapshotStats,
    _write_attack_paths,
    _write_edges,
    _write_interaction_risks,
    _write_nodes,
    _write_snapshot_paths,
    _write_snapshot_row,
)
from agent_bom.db.graph_write_admission import graph_writer_admission
from agent_bom.graph import (
    AttackPath,
    EntityType,
    InteractionRisk,
    NodeDimensions,
    NodeStatus,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
    _now_iso,
)
from agent_bom.graph.analysis import (
    GraphAnalysisStatus,
    analysis_status_map_from_dict,
    not_recorded_analysis_status,
)
from agent_bom.graph.container import GraphCompleteness, resolve_node_budget
from agent_bom.graph.severity_floor import severity_floor_sql
from agent_bom.graph.snapshot_paths import SnapshotPath, prepare_snapshot_paths
from agent_bom.security import sanitize_text
from agent_bom.storage import sqlite_wal, state_home

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Schema DDL — scan_id is part of every PK for per-scan isolation
# ═══════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════
# Connection helpers
# ═══════════════════════════════════════════════════════════════════════════


def _backfill_empty_tenant_ids(conn: sqlite3.Connection, table_keys: dict[str, tuple[str, ...]] | None = None) -> None:
    """Move legacy ``tenant_id = ''`` rows into the default graph tenant.

    When a default-tenant row already exists for the same graph key, keep the
    explicit default row and drop the duplicate legacy row before updating.
    """

    specs = table_keys or _GRAPH_TENANT_TABLE_KEYS
    for table, key_columns in specs.items():
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'virtual') AND name = ?",
            (table,),
        ).fetchone()
        if table_exists is None:
            continue
        if key_columns:
            key_match = " AND ".join(f"existing.{column} = {table}.{column}" for column in key_columns)
            conn.execute(
                f"""
                DELETE FROM {table}
                WHERE tenant_id = ''
                  AND EXISTS (
                    SELECT 1
                    FROM {table} existing
                    WHERE existing.tenant_id = ?
                      AND {key_match}
                  )
                """,  # nosec B608 - table/key names are static internal schema metadata
                (DEFAULT_GRAPH_TENANT_ID,),
            )
        conn.execute(
            f"UPDATE {table} SET tenant_id = ? WHERE tenant_id = ''",  # nosec B608 - table names are static internal schema metadata
            (DEFAULT_GRAPH_TENANT_ID,),
        )


def default_graph_db_path() -> Path:
    """Resolve the graph DB path from the active deployment configuration.

    Preference order:
    1. ``AGENT_BOM_GRAPH_DB`` explicit graph database path
    2. ``AGENT_BOM_DB`` shared SQLite database used by the API
    3. ``<state dir>/db/graph.db`` via :mod:`agent_bom.storage.state_home`
       (``AGENT_BOM_STATE_DIR``, else ``~/.agent-bom``; the demo estate pins it
       to its own directory)
    """
    configured = os.environ.get("AGENT_BOM_GRAPH_DB") or os.environ.get("AGENT_BOM_DB")
    if configured:
        return Path(configured).expanduser()
    return state_home.state_path("db", "graph.db")


def _init_db(conn: sqlite3.Connection, *, backfill_legacy_tenants: bool = True) -> None:
    """Ensure tables exist and schema is current."""
    sqlite_wal.enable_wal(conn, wait_seconds=10.0)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_CREATE_TABLES)
    conn.execute("BEGIN IMMEDIATE")  # Reserve the writer before schema inspection/backfill.
    row = conn.execute("SELECT version FROM graph_schema_version ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        conn.execute(
            "INSERT OR IGNORE INTO graph_schema_version (version) VALUES (?)",
            (_GRAPH_SCHEMA_VERSION,),
        )
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(attack_paths)").fetchall()}
    if "summary" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN summary TEXT DEFAULT ''")
    if "tool_exposure" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN tool_exposure TEXT DEFAULT '[]'")
    if "technique_mappings" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN technique_mappings TEXT DEFAULT '[]'")
    if "reachability" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN reachability TEXT DEFAULT 'unknown'")
    if "reachability_basis" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN reachability_basis TEXT DEFAULT '[]'")
    if "hop_evidence" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN hop_evidence TEXT DEFAULT '[]'")
    if "analysis" not in existing_columns:
        conn.execute("ALTER TABLE attack_paths ADD COLUMN analysis TEXT DEFAULT '{}'")
    upgrade_attack_path_identity(conn)
    edge_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_edges)").fetchall()}
    # v3 adds replay metadata. Empty valid_from is interpreted as first_seen for
    # stores created before this migration, so old snapshots remain queryable.
    edge_migrations = {
        "valid_from": "ALTER TABLE graph_edges ADD COLUMN valid_from TEXT DEFAULT ''",
        "valid_to": "ALTER TABLE graph_edges ADD COLUMN valid_to TEXT DEFAULT NULL",
        "confidence": "ALTER TABLE graph_edges ADD COLUMN confidence REAL DEFAULT 1.0",
        "provenance": "ALTER TABLE graph_edges ADD COLUMN provenance TEXT DEFAULT '{}'",
        "source_scan_id": "ALTER TABLE graph_edges ADD COLUMN source_scan_id TEXT DEFAULT ''",
        "source_run_id": "ALTER TABLE graph_edges ADD COLUMN source_run_id TEXT DEFAULT ''",
    }
    for column, statement in edge_migrations.items():
        if column not in edge_columns:
            conn.execute(statement)
    backfill_edge_metadata(conn)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_tenant_valid ON graph_edges(tenant_id, valid_from, valid_to)")
    # Backfill the per-hop traversal indexes onto stores created before them.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan_source ON graph_edges(tenant_id, scan_id, source_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan_target ON graph_edges(tenant_id, scan_id, target_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_adjacency_out ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ge_adjacency_in ON graph_edges(tenant_id, scan_id, target_id, source_id, relationship)")
    # Materialise the per-snapshot entity-type breakdown so inventory/summary
    # reads a cached count instead of a per-request GROUP BY over every node.
    # NULL marks pre-migration snapshots, which fall back to the live GROUP BY.
    snapshot_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_snapshots)").fetchall()}
    if "node_type_counts" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN node_type_counts TEXT DEFAULT NULL")
    if "analysis_status" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN analysis_status TEXT DEFAULT '{}'")
    if "snapshot_kind" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN snapshot_kind TEXT NOT NULL DEFAULT 'scan'")
    if "correlation_id" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN correlation_id TEXT DEFAULT NULL")
    if "evidence_manifest_sha256" not in snapshot_columns:
        conn.execute("ALTER TABLE graph_snapshots ADD COLUMN evidence_manifest_sha256 TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_revisions(conn, snapshot_columns)
    correlation_columns = {row["name"] for row in conn.execute("PRAGMA table_info(graph_correlation_runs)").fetchall()}
    if "result_manifest" not in correlation_columns:
        conn.execute("ALTER TABLE graph_correlation_runs ADD COLUMN result_manifest TEXT NOT NULL DEFAULT '{}'")
    if "execution_owner" not in correlation_columns:
        conn.execute("ALTER TABLE graph_correlation_runs ADD COLUMN execution_owner TEXT NOT NULL DEFAULT ''")
    if "execution_lease_expires_at" not in correlation_columns:
        conn.execute("ALTER TABLE graph_correlation_runs ADD COLUMN execution_lease_expires_at TEXT NOT NULL DEFAULT ''")
    conn.execute("INSERT OR IGNORE INTO graph_schema_version (version) VALUES (?)", (_GRAPH_SCHEMA_VERSION,))
    if backfill_legacy_tenants:
        _backfill_empty_tenant_ids(conn)
    conn.commit()


def _graph_write_batch_size() -> int:
    raw = os.environ.get("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", str(_DEFAULT_GRAPH_WRITE_BATCH_SIZE))
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_GRAPH_WRITE_BATCH_SIZE


def graph_retention_policy(
    conn: sqlite3.Connection | None = None,
    *,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Describe the active graph retention policy.

    When a connection is supplied, the response reflects real enforcement state
    (``last_purge_at`` / ``last_purged_count``) recorded by
    :func:`purge_expired_graph_snapshots`, rather than metadata alone.

    Pass ``tenant_id`` to resolve the effective retention window for one tenant
    (store override, env JSON map, then global default).
    """
    from agent_bom.api.tenant_graph_retention import graph_retention_overrides_snapshot, resolve_graph_retention_days

    normalized_tenant = normalize_graph_tenant_id(tenant_id) if tenant_id is not None else None
    policy: dict[str, Any] = {
        "retention_days": resolve_graph_retention_days(normalized_tenant),
        "default_retention_days": _graph_retention_days(),
        "mode": "queryable_snapshot_history",
        "deletion_state": "active",
        "enforcement": "age_based_purge_on_save",
        "legal_hold": False,
        **graph_retention_overrides_snapshot(),
    }
    if normalized_tenant is not None:
        policy["tenant_id"] = normalized_tenant
    if conn is not None:
        last_purge_at, last_purged_count = _read_purge_state(conn)
        policy["last_purge_at"] = last_purge_at
        policy["last_purged_count"] = last_purged_count
    return policy


def purge_expired_graph_snapshots(
    conn: sqlite3.Connection,
    *,
    retention_days: int | None = None,
    now: datetime | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Delete graph snapshots older than the retention window and their rows.

    Age-based purge keyed on ``graph_snapshots.created_at``. Runs across every
    tenant by default; pass ``tenant_id`` to scope the purge to a single tenant.

    Fail-closed: a snapshot whose ``created_at`` cannot be parsed as an ISO-8601
    timestamp is *retained*, never deleted, so malformed rows can never trigger
    unintended data loss. Deletes cascade to ``graph_nodes``, ``graph_edges``,
    ``attack_paths`` and ``interaction_risks`` for the same ``(scan_id,
    tenant_id)`` pair, plus the API search index when present.
    """
    from agent_bom.api.tenant_graph_retention import resolve_graph_retention_days_by_tenant as by_tenant

    fixed_days = None if retention_days is None else max(1, int(retention_days))
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    query = "SELECT scan_id, tenant_id, created_at FROM graph_snapshots"
    params: list[Any] = []
    if tenant_id is not None:
        query += " WHERE tenant_id = ?"
        params.append(normalize_graph_tenant_id(tenant_id))
    rows = conn.execute(query, params).fetchall()

    expired: list[tuple[str, str]] = []
    resolved_days = {} if fixed_days is not None else by_tenant({str(row[1]) for row in rows}, all_tenants=tenant_id is None)
    for row in rows:
        tid = str(row[1])
        days = fixed_days if fixed_days is not None else resolved_days[tid]
        cutoff = now_dt - timedelta(days=days)
        created = _parse_iso_timestamp(row[2])
        if created is not None and created < cutoff:
            expired.append((str(row[0]), tid))

    if expired:
        for table in _GRAPH_PURGEABLE_TABLES:
            conn.executemany(
                f"DELETE FROM {table} WHERE scan_id = ? AND tenant_id = ?",  # nosec B608 - table names are static internal schema metadata
                expired,
            )
        if _table_exists(conn, "graph_node_search"):
            conn.executemany(
                "DELETE FROM graph_node_search WHERE scan_id = ? AND tenant_id = ?",
                expired,
            )

    purged_at = _now_iso()
    _record_purge_state(conn, purged_count=len(expired), purged_at=purged_at)
    conn.commit()

    effective_days = fixed_days if fixed_days is not None else _graph_retention_days()
    return {
        "retention_days": effective_days,
        "per_tenant_retention_days": dict(resolved_days) if fixed_days is None and resolved_days else None,
        "cutoff": (now_dt - timedelta(days=effective_days)).isoformat(),
        "purged_count": len(expired),
        "last_purge_at": purged_at,
        "purged_snapshots": [{"scan_id": scan_id, "tenant_id": tid} for scan_id, tid in expired],
    }


# ``PRAGMA optimize`` runs ANALYZE only where SQLite judges the statistics
# stale, so the steady-state cost is nil (measured: 96.8 ms on the first pass
# over a 300k-node store, 0.02 ms on every pass after it). The 0x10000 bit asks
# it to consider every table rather than only those this connection happened to
# query, which SQLite's documentation recommends for a connection that has no
# query history — the write connections here are short-lived and open with
# none. 0x00002 is "actually run ANALYZE" and is on by default; it is named
# explicitly so the intent survives a future default change.
#
# Since SQLite 3.46 the command self-limits its own scope, so this stays bounded
# on an arbitrarily large store without ``PRAGMA analysis_limit``.
_PLANNER_STATS_PRAGMA = "PRAGMA optimize=0x10002"


def refresh_query_planner_stats(conn: sqlite3.Connection) -> None:
    """Record/refresh planner statistics for this database.

    Without ``sqlite_stat1`` the planner's choice between two indexes that share
    a leading column prefix is — in SQLite's own words — *arbitrary*, and
    ``graph_nodes`` deliberately carries such a pair: ``idx_gn_tenant_scan`` for
    reads that want a snapshot in rowid order, ``idx_gn_tenant_scan_rank`` for
    the paged reads that want it in severity order. Neither index can serve both
    orders, so the read path cannot be made correct by index shape alone; it
    needs the planner to be able to tell the two queries apart. Measured at 300k
    rows, an arbitrary tie-break cost the full-snapshot read 533.8 ms -> 640.1 ms.

    Never fatal. Statistics are an optimisation, and a store that cannot record
    them (a read-only mount, a concurrent writer holding the lock) must still
    serve reads rather than fail the write that triggered the refresh.
    """
    try:
        conn.execute(_PLANNER_STATS_PRAGMA)
        conn.commit()
    except sqlite3.Error:  # pragma: no cover - defensive, see docstring
        pass


@contextmanager
def open_graph_db(db_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    """Open (or create) a graph database with schema initialisation."""
    target = str(db_path)
    # Create the parent directory up front: on a fresh deploy (new volume /
    # container, offline) ``~/.agent-bom/db`` may not exist yet, and
    # ``sqlite3.connect`` does not create missing parents — it raises
    # "unable to open database file", which silently leaves the seeded demo
    # estate with an empty graph. ``:memory:`` has no parent to create.
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    with graph_writer_admission(db_path):
        conn = sqlite3.connect(target, timeout=10)
        conn.row_factory = sqlite3.Row
        completed = False
        try:
            _init_db(conn)
            yield conn
            completed = True
        finally:
            # Stats refresh commits: skip it after producer failure so closing
            # rolls back the partial write and preserves the previous snapshot.
            if completed:
                refresh_query_planner_stats(conn)
            conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# Write — each scan is an immutable snapshot (INSERT OR REPLACE by PK)
# ═══════════════════════════════════════════════════════════════════════════


def save_graph(conn: sqlite3.Connection, graph: UnifiedGraph) -> None:
    """Persist a UnifiedGraph as an immutable per-scan snapshot.

    Thin wrapper over :func:`save_graph_streaming` — the streamed path never
    holds more than one write batch in memory; prior-edge lifecycle
    reconciliation is database-side, so peak RSS is decoupled from both the
    incoming and previous graph sizes (see #4055/#4075). Callers that
    already hold a fully built ``UnifiedGraph`` keep the same behaviour; callers
    that can produce nodes/edges lazily should call ``save_graph_streaming``
    directly with generators to avoid materialising the whole graph.
    """
    save_graph_streaming(
        conn,
        scan_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        created_at=graph.created_at,
        nodes=graph.nodes.values(),
        edges=graph.edges,
        attack_paths=graph.attack_paths,
        interaction_risks=graph.interaction_risks,
        analysis_status=graph.analysis_status,
        snapshot_paths=prepare_snapshot_paths(graph),
    )


def save_graph_streaming(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    tenant_id: str = "",
    nodes: Iterable[UnifiedNode],
    edges: Iterable[UnifiedEdge],
    attack_paths: Iterable[AttackPath] = (),
    interaction_risks: Iterable[InteractionRisk] = (),
    analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
    created_at: str = "",
    snapshot_kind: str = "scan",
    correlation_id: str = "",
    evidence_manifest_sha256: str = "",
    write_generation: str = "",
    correlation_result_manifest: Mapping[str, Any] | None = None,
    correlation_completed_at: str = "",
    correlation_execution_owner: str = "",
    snapshot_paths: Sequence[SnapshotPath] | None = None,
) -> dict[str, int]:
    """Persist a graph snapshot from streamed node/edge iterables.

    ``nodes``/``edges`` are consumed lazily in bounded batches with stats
    accumulated incrementally, so peak RSS stays flat (#4055); writes are
    byte-identical to ``save_graph``. ``snapshot_paths`` become the snapshot's
    stored path index in the same transaction.

    Precondition — the caller must yield **deduplicated** items: unique node
    ``id`` and unique ``(source, target, relationship)`` edge keys, exactly the
    invariant :class:`~agent_bom.graph.UnifiedGraph` maintains for the
    ``save_graph`` caller. The stat counters (``node_count`` / ``edge_count`` /
    severity / type breakdowns) count each *yield* — they intentionally do NOT
    hold a seen-set, because that would reintroduce the O(n) memory this path
    exists to avoid. Persisted *rows* still dedupe via ``INSERT OR REPLACE`` on
    the primary key, so a duplicate-yielding producer would leave the stat
    columns over-counting the deduped row totals. Pass a pre-deduplicated
    iterable (a ``UnifiedGraph``'s ``nodes.values()`` / ``edges`` always is).

    Returns the persisted ``{"nodes": N, "edges": M}`` counts.
    """
    tenant = normalize_graph_tenant_id(tenant_id)
    scan = scan_id
    now = created_at or _now_iso()
    _check_snapshot_writable(conn, tenant=tenant, scan=scan, snapshot_kind=snapshot_kind, correlation_id=correlation_id)
    batch_size = _graph_write_batch_size()
    # Derived correlations combine evidence; they are not a new observation
    # and must neither inherit scan continuity nor retire source-scan edges.
    previous_scan = latest_snapshot_id(conn, tenant_id=tenant) if snapshot_kind == "scan" else ""
    if previous_scan == scan:
        previous_scan = previous_snapshot_id(conn, tenant_id=tenant, before_scan_id=scan)
    _clear_snapshot_rows(conn, tenant=tenant, scan=scan)

    stats = _SnapshotStats()
    _write_nodes(conn, nodes, stats, scan=scan, tenant=tenant, batch_size=batch_size)
    _write_edges(conn, edges, stats, scan=scan, tenant=tenant, now=now, batch_size=batch_size)
    if previous_scan:
        _carry_forward_edge_continuity(conn, previous_scan=previous_scan, scan=scan, tenant=tenant)
    # A later snapshot does not prove a removed native relationship. Preserve
    # source-supplied ends; unknown/partial collection never synthesizes Close.
    attack_path_count = _write_attack_paths(conn, attack_paths, scan=scan, tenant=tenant, now=now)
    _write_interaction_risks(conn, interaction_risks, scan=scan, tenant=tenant)
    _write_snapshot_row(
        conn,
        stats,
        scan=scan,
        tenant=tenant,
        now=now,
        analysis_status=analysis_status,
        snapshot_kind=snapshot_kind,
        correlation_id=correlation_id,
        evidence_manifest_sha256=evidence_manifest_sha256,
        write_generation=write_generation,
    )
    _write_snapshot_paths(conn, snapshot_paths, scan=scan, tenant=tenant, now=now)
    if correlation_result_manifest is not None:
        _complete_correlation_run_atomically(
            conn,
            tenant=tenant,
            scan=scan,
            correlation_id=correlation_id,
            evidence_manifest_sha256=evidence_manifest_sha256,
            correlation_result_manifest=correlation_result_manifest,
            completed_at=correlation_completed_at or now,
            execution_owner=correlation_execution_owner,
        )
    node_count, edge_count = stats.node_count, stats.edge_count

    conn.commit()
    logger.info(
        "Saved graph: %d nodes, %d edges, %d attack paths (scan=%s)",
        node_count,
        edge_count,
        attack_path_count,
        scan,
    )

    # Enforce age-based retention on the post-save lifecycle hook. A purge
    # failure must never fail the durable save that already committed above, so
    # it is best-effort and logged with sanitized text.
    try:
        result = purge_expired_graph_snapshots(conn)
        if result["purged_count"]:
            logger.info("Purged %d expired graph snapshot(s)", result["purged_count"])
    except Exception as exc:  # noqa: BLE001 - includes retention-store errors; nothing is deleted before they raise
        logger.warning("Graph snapshot retention purge skipped: %s", sanitize_text(str(exc)))

    return {"nodes": node_count, "edges": edge_count}


# ═══════════════════════════════════════════════════════════════════════════
# Read — load exactly one scan's snapshot
# ═══════════════════════════════════════════════════════════════════════════


def load_graph(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    entity_types: set[str] | None = None,
    min_severity_rank: int = 0,
    relationship_types: frozenset[str] | None = None,
    node_budget: int | None = None,
) -> UnifiedGraph:
    """Load a UnifiedGraph from a specific scan snapshot.

    ``node_budget`` bounds the read in SQL and is reported on
    ``graph.completeness``; it defaults to unbounded because callers that
    compute differences (snapshot diff, compare) are only correct on a whole
    graph — a trimmed one reads as deletions that never happened.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
    if not effective_scan_id:
        return graph

    snapshot_row = conn.execute(
        "SELECT analysis_status FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
        (tenant_id, effective_scan_id),
    ).fetchone()
    if snapshot_row is not None:
        raw_status = json.loads(snapshot_row["analysis_status"] or "{}")
        graph.analysis_status = analysis_status_map_from_dict(raw_status)
        if not graph.analysis_status:
            graph.analysis_status["attack_path_fusion"] = not_recorded_analysis_status()

    where = "tenant_id = ? AND scan_id = ?"
    params: list[Any] = [tenant_id, effective_scan_id]
    if entity_types:
        placeholders = ",".join("?" * len(entity_types))
        where += f" AND entity_type IN ({placeholders})"
        params.extend(entity_types)
    sev_sql, sev_params = severity_floor_sql(min_severity_rank)
    if sev_sql:
        where += f" AND {sev_sql}"
        params.extend(sev_params)

    query = f"SELECT * FROM graph_nodes WHERE {where}"  # nosec B608 - where is built from static clause fragments
    budget = resolve_node_budget(node_budget)
    total_nodes = 0
    if budget is not None:
        # The budget has to bound the *read*, not the result. Trimming after a
        # full materialization declares the same completeness while still having
        # paid for every row: at 200k nodes that is ~783 MB the cap was
        # introduced to avoid. Risk-ranked so a trimmed view keeps what matters,
        # id breaking ties so the selection is deterministic — the same order
        # Postgres uses, so the two backends return the same nodes.
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM graph_nodes WHERE {where}",  # nosec B608 - where is built from static clause fragments
            params,
        ).fetchone()
        total_nodes = int(count_row[0]) if count_row else 0
        query += " ORDER BY risk_score DESC, id LIMIT ?"
        params.append(budget)
    else:
        # One explicit order, shared with Postgres, independent of the planner's
        # index choice. Correlation receipts hash the ordered snapshot serialization.
        query += " ORDER BY id"

    node_ids: set[str] = set()
    for row in conn.execute(query, params):
        sev = row["severity"] or ""
        graph.add_node(
            UnifiedNode(
                id=row["id"],
                entity_type=EntityType(row["entity_type"]),
                label=row["label"],
                category_uid=row["category_uid"],
                class_uid=row["class_uid"],
                type_uid=row["type_uid"],
                status=NodeStatus(row["status"]),
                risk_score=row["risk_score"],
                severity=sev,
                severity_id=row["severity_id"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                attributes=json.loads(row["attributes"]),
                compliance_tags=json.loads(row["compliance_tags"]),
                data_sources=json.loads(row["data_sources"]),
                dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
            )
        )
        node_ids.add(row["id"])

    returned_nodes = len(node_ids)
    if budget is None:
        total_nodes = returned_nodes
    graph.completeness = GraphCompleteness(
        truncated=budget is not None and total_nodes > returned_nodes,
        node_budget=budget,
        total_nodes=total_nodes,
        returned_nodes=returned_nodes,
        reason="node_budget" if budget is not None and total_nodes > returned_nodes else "",
    )

    sql_scoped_edges = budget is not None or bool(entity_types) or bool(sev_sql)
    if sql_scoped_edges:
        # Drive the edge read from the exact node ids loaded above. Encoding the
        # bounded set as one JSON parameter avoids SQLite's variable limit and
        # avoids repeating the ranked node query. The endpoint index makes the
        # work proportional to edges touching those nodes instead of every edge
        # in the snapshot; the second join preserves the induced-subgraph
        # contract.
        eq = """
            WITH selected_node_ids AS MATERIALIZED (
                SELECT CAST(value AS TEXT) AS id FROM json_each(?)
            )
            SELECT edge.*
            FROM selected_node_ids AS source_node
            CROSS JOIN graph_edges AS edge INDEXED BY idx_ge_tenant_scan_source
            JOIN selected_node_ids AS target_node
              ON target_node.id = edge.target_id
            WHERE edge.tenant_id = ?
              AND edge.scan_id = ?
              AND edge.source_id = source_node.id
        """
        eparams: list[Any] = [json.dumps(sorted(node_ids)), tenant_id, effective_scan_id]
    else:
        eq = "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ?"
        eparams = [tenant_id, effective_scan_id]
    if relationship_types:
        placeholders = ",".join("?" * len(relationship_types))
        eq += f" AND edge.relationship IN ({placeholders})" if sql_scoped_edges else f" AND relationship IN ({placeholders})"
        eparams.extend(sorted(relationship_types))
    # A snapshot's evidence must serialize identically across SQLite versions
    # and query plans. Keep the established source/target/relationship order.
    edge_prefix = "edge." if sql_scoped_edges else ""
    eq += f" ORDER BY {edge_prefix}source_id, {edge_prefix}target_id, {edge_prefix}relationship"
    for row in conn.execute(eq, eparams):
        if row["source_id"] not in node_ids or row["target_id"] not in node_ids:
            continue
        graph.add_stored_edge(
            UnifiedEdge(
                source=row["source_id"],
                target=row["target_id"],
                relationship=RelationshipType(row["relationship"]),
                direction=row["direction"],
                weight=row["weight"],
                traversable=bool(row["traversable"]),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                valid_from=row["valid_from"] or row["first_seen"],
                valid_to=row["valid_to"],
                confidence=row["confidence"],
                provenance=json.loads(row["provenance"] or "{}"),
                source_scan_id=row["source_scan_id"] or row["scan_id"],
                source_run_id=row["source_run_id"] or "",
                evidence=json.loads(row["evidence"]),
                activity_id=row["activity_id"],
            )
        )

    if not relationship_types:
        apq = f"SELECT {ATTACK_PATH_SELECT} FROM attack_paths WHERE tenant_id = ? AND scan_id = ? ORDER BY {ATTACK_PATH_ORDER}"  # nosec B608
        graph.attack_paths.extend(attack_path_from_row(row) for row in conn.execute(apq, (tenant_id, effective_scan_id)))

        irq = "SELECT * FROM interaction_risks WHERE tenant_id = ? AND scan_id = ? ORDER BY rowid"
        irparams: list[Any] = [tenant_id, effective_scan_id]
        for row in conn.execute(irq, irparams):
            graph.interaction_risks.append(
                InteractionRisk(
                    pattern=row["pattern"],
                    agents=json.loads(row["agents"]),
                    risk_score=row["risk_score"],
                    description=row["description"],
                    owasp_agentic_tag=row["owasp_agentic_tag"],
                )
            )

    return graph


# ═══════════════════════════════════════════════════════════════════════════
# Diff / temporal queries
# ═══════════════════════════════════════════════════════════════════════════


def _snapshot_digests(conn: sqlite3.Connection, *, tenant_id: str, scan_id: str) -> tuple[str, str, dict[str, int]]:
    graph_rows: dict[str, list[dict[str, Any]]] = {"nodes": [], "edges": []}
    finding_rows: dict[str, list[dict[str, Any]]] = {"findings": [], "attack_paths": [], "compliance": []}

    for row in conn.execute(
        """
        SELECT id, entity_type, label, status, severity, severity_id, risk_score,
               compliance_tags, data_sources
        FROM graph_nodes
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY id
        """,
        (tenant_id, scan_id),
    ):
        node = {
            "id": row["id"],
            "entity_type": row["entity_type"],
            "label": row["label"],
            "status": row["status"],
            "severity": row["severity"] or "",
            "severity_id": int(row["severity_id"] or 0),
            "risk_score": float(row["risk_score"] or 0.0),
            "compliance_tags": json.loads(row["compliance_tags"] or "[]"),
            "data_sources": json.loads(row["data_sources"] or "[]"),
        }
        graph_rows["nodes"].append(node)
        if row["entity_type"] in _FINDING_ENTITY_TYPES:
            finding_rows["findings"].append(node)
        for tag in node["compliance_tags"]:
            finding_rows["compliance"].append({"node_id": row["id"], "tag": tag})

    for row in conn.execute(
        """
        SELECT source_id, target_id, relationship, direction, weight, traversable,
               valid_from, valid_to, confidence, activity_id
        FROM graph_edges
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY source_id, target_id, relationship
        """,
        (tenant_id, scan_id),
    ):
        graph_rows["edges"].append(
            {
                "source_id": row["source_id"],
                "target_id": row["target_id"],
                "relationship": row["relationship"],
                "direction": row["direction"],
                "weight": float(row["weight"] or 0.0),
                "traversable": bool(row["traversable"]),
                "valid_from": row["valid_from"] or "",
                "valid_to": row["valid_to"] or "",
                "confidence": float(row["confidence"] if row["confidence"] is not None else 1.0),
                "activity_id": int(row["activity_id"] or 1),
            }
        )

    for row in conn.execute(
        """
        SELECT source_node, target_node, hop_count, composite_risk, summary,
               path_nodes, path_edges, credential_exposure, tool_exposure, vuln_ids,
               reachability, reachability_basis, technique_mappings, hop_evidence, analysis
        FROM attack_paths
        WHERE tenant_id = ? AND scan_id = ?
        ORDER BY source_node, target_node, path_key
        """,
        (tenant_id, scan_id),
    ):
        finding_rows["attack_paths"].append(
            {
                "source_node": row["source_node"],
                "target_node": row["target_node"],
                "hop_count": int(row["hop_count"] or 0),
                "composite_risk": float(row["composite_risk"] or 0.0),
                "summary": row["summary"] or "",
                "path_nodes": json.loads(row["path_nodes"] or "[]"),
                "path_edges": json.loads(row["path_edges"] or "[]"),
                "credential_exposure": json.loads(row["credential_exposure"] or "[]"),
                "tool_exposure": json.loads(row["tool_exposure"] or "[]"),
                "vuln_ids": json.loads(row["vuln_ids"] or "[]"),
                "reachability": row["reachability"] or "unknown",
                "reachability_basis": json.loads(row["reachability_basis"] or "[]"),
                "technique_mappings": json.loads(row["technique_mappings"] or "[]"),
                "hop_evidence": json.loads(row["hop_evidence"] or "[]"),
                "analysis": json.loads(row["analysis"] or "{}"),
            }
        )

    counts = {
        "nodes": len(graph_rows["nodes"]),
        "edges": len(graph_rows["edges"]),
        "findings": len(finding_rows["findings"]),
        "attack_paths": len(finding_rows["attack_paths"]),
        "compliance_tags": len(finding_rows["compliance"]),
    }
    return _digest_payload(graph_rows), _digest_payload(finding_rows), counts


def graph_evidence_manifest(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    scan_id: str = "",
    baseline_scan_id: str = "",
) -> dict[str, Any]:
    """Build a redaction-aware evidence manifest for one retained graph snapshot."""
    tenant_id = normalize_graph_tenant_id(tenant_id)
    effective_scan_id, created_at = _resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
    if not effective_scan_id:
        return {
            "schema_version": "agent-bom.graph_evidence_manifest/v1",
            "tenant_id": tenant_id,
            "scan_id": "",
            "generated_at": _now_iso(),
            "retention_policy": graph_retention_policy(conn),
            "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
            "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
        }

    baseline = baseline_scan_id or previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=effective_scan_id)
    graph_digest, findings_digest, counts = _snapshot_digests(conn, tenant_id=tenant_id, scan_id=effective_scan_id)
    diff_summary = _diff_summary_counts(diff_snapshots(conn, baseline, effective_scan_id, tenant_id=tenant_id)) if baseline else {}

    return {
        "schema_version": "agent-bom.graph_evidence_manifest/v1",
        "tenant_id": tenant_id,
        "scan_id": effective_scan_id,
        "generated_at": _now_iso(),
        "scan_created_at": created_at,
        "graph_digest": graph_digest,
        "findings_digest": findings_digest,
        "diff_baseline_scan_id": baseline,
        "diff_summary": diff_summary,
        "counts": counts,
        "included_tables": list(_GRAPH_EVIDENCE_INCLUDED_TABLES),
        "excluded_private_fields": list(_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS),
        "retention_policy": graph_retention_policy(conn),
    }


def graph_history(
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "",
    limit: int = 50,
    since: str | None = None,
) -> dict[str, Any]:
    """Return retained graph snapshot history with adjacent diff summaries.

    ``since`` bounds the returned snapshots to the read window (ISO-8601 cutoff);
    ``None`` returns all retained history.
    """
    tenant_id = normalize_graph_tenant_id(tenant_id)
    snapshots = list_snapshots(conn, tenant_id=tenant_id, limit=limit, since=since)
    history: list[dict[str, Any]] = []
    for snapshot in snapshots:
        scan_id = snapshot["scan_id"]
        baseline = previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=scan_id)
        diff_summary = _diff_summary_counts(diff_snapshots(conn, baseline, scan_id, tenant_id=tenant_id)) if baseline else {}
        history.append(
            {
                **snapshot,
                "diff_baseline_scan_id": baseline,
                "diff_summary": diff_summary,
            }
        )
    return {
        "schema_version": "agent-bom.graph_history/v1",
        "tenant_id": tenant_id,
        "retention_policy": graph_retention_policy(conn),
        "snapshots": history,
    }
