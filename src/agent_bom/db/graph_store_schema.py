"""Graph store schema DDL, shared constants and low-level SQLite helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Sequence

if TYPE_CHECKING:
    pass

from agent_bom.core.settings import env_raw
from agent_bom.graph import (
    AttackPath,
    EntityType,
    technique_mappings_from_json,
)
from agent_bom.graph.snapshot_paths import occurrence_path_keys

logger = logging.getLogger("agent_bom.db.graph_store")


DEFAULT_GRAPH_TENANT_ID = "default"


GRAPH_SNAPSHOT_KINDS = frozenset({"scan", "correlation"})


_GRAPH_SCHEMA_VERSION = 8


_DEFAULT_GRAPH_WRITE_BATCH_SIZE = 1000


_DEFAULT_GRAPH_RETENTION_DAYS = 180


_FINDING_ENTITY_TYPES = {
    EntityType.VULNERABILITY.value,
    EntityType.MISCONFIGURATION.value,
    EntityType.DRIFT_INCIDENT.value,
}


_GRAPH_EVIDENCE_INCLUDED_TABLES = [
    "graph_snapshots",
    "graph_nodes",
    "graph_edges",
    "attack_paths",
    "interaction_risks",
]


_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS = [
    "graph_nodes.attributes",
    "graph_edges.provenance",
    "graph_edges.evidence",
    "attack_paths.credential_exposure",
]


_GRAPH_TENANT_TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "graph_nodes": ("id", "scan_id"),
    "graph_edges": ("source_id", "target_id", "relationship", "scan_id"),
    "graph_snapshots": ("scan_id",),
    "graph_correlation_runs": ("correlation_id",),
    "attack_paths": ("path_key", "scan_id"),
    "interaction_risks": ("pattern", "agents", "scan_id"),
}


_ATTACK_PATHS_DDL = """\
CREATE TABLE IF NOT EXISTS attack_paths (
    source_node     TEXT NOT NULL,
    target_node     TEXT NOT NULL,
    hop_count       INTEGER DEFAULT 0,
    composite_risk  REAL DEFAULT 0.0,
    summary         TEXT DEFAULT '',
    path_nodes      TEXT DEFAULT '[]',
    path_edges      TEXT DEFAULT '[]',
    credential_exposure TEXT DEFAULT '[]',
    tool_exposure   TEXT DEFAULT '[]',
    vuln_ids        TEXT DEFAULT '[]',
    reachability    TEXT DEFAULT 'unknown',
    reachability_basis TEXT DEFAULT '[]',
    technique_mappings TEXT DEFAULT '[]',
    hop_evidence     TEXT DEFAULT '[]',
    analysis         TEXT DEFAULT '{}',
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    computed_at     TEXT NOT NULL,
    finding_ids     TEXT DEFAULT '[]',
    -- snapshot_paths.occurrence_path_keys: hop/edge chain hash, ordinal-suffixed on repeats.
    path_key        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, scan_id, path_key)
);
"""

_ATTACK_PATH_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_ap_risk ON attack_paths(composite_risk DESC);
CREATE INDEX IF NOT EXISTS idx_ap_scan ON attack_paths(scan_id);
CREATE INDEX IF NOT EXISTS idx_ap_tenant_scan ON attack_paths(tenant_id, scan_id);
"""


_CREATE_TABLES = (
    """\
-- ── Graph nodes (one row per node per scan) ──
CREATE TABLE IF NOT EXISTS graph_nodes (
    id              TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    label           TEXT NOT NULL,
    -- OCSF projection columns (derived from entity_type via graph/ocsf.py
    -- ENTITY_OCSF_MAP) for classification/filtering. They are not the
    -- canonical source of truth for graph entities.
    category_uid    INTEGER DEFAULT 0,
    class_uid       INTEGER DEFAULT 0,
    type_uid        INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'active',
    risk_score      REAL DEFAULT 0.0,
    severity        TEXT DEFAULT '',
    severity_id     INTEGER DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    attributes      TEXT DEFAULT '{}',
    compliance_tags TEXT DEFAULT '[]',
    data_sources    TEXT DEFAULT '[]',
    dimensions      TEXT DEFAULT '{}',
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (id, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_gn_entity_type ON graph_nodes(entity_type);
CREATE INDEX IF NOT EXISTS idx_gn_severity ON graph_nodes(severity);
CREATE INDEX IF NOT EXISTS idx_gn_risk ON graph_nodes(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_gn_scan ON graph_nodes(scan_id);
CREATE INDEX IF NOT EXISTS idx_gn_tenant_scan ON graph_nodes(tenant_id, scan_id);
-- Node paging order, in index form. page_nodes() equality-filters on
-- (tenant_id, scan_id) then sorts by (severity_id DESC, risk_score DESC,
-- label ASC, id ASC) -- the same tuple the keyset cursor encodes. With only
-- idx_gn_tenant_scan the planner answered every page with "USE TEMP B-TREE FOR
-- ORDER BY", materialising and sorting the WHOLE snapshot to return one page:
-- cost O(snapshot log snapshot) per request regardless of limit. Carrying the
-- sort columns in the index makes the scan pre-ordered, so a page is a range
-- read. Column order and direction must keep matching the ORDER BY exactly or
-- SQLite silently falls back to the temp B-tree.
--
-- This index and idx_gn_tenant_scan above are a deliberate pair, and BOTH are
-- required. They share the (tenant_id, scan_id) prefix, so either can answer
-- the unordered full-snapshot read that load_graph() issues -- but they hold
-- their rows in different orders, and that decides the cost. This one is
-- ordered by severity, so walking it to fetch the non-indexed columns hits the
-- table in scattered rowid order; idx_gn_tenant_scan is ordered by rowid within
-- a snapshot and hits it sequentially. Measured at 300k rows:
--
--     read              idx_gn_tenant_scan only   both indexes, with stats
--     full snapshot                    533.8 ms                   528.4 ms
--     one 500-row page                  35.1 ms                     1.0 ms
--
-- Adding this index therefore fixed paging (35.1 -> 1.0 ms) and, until the
-- planner was given statistics, regressed the full read to 640.1 ms, because
-- SQLite's documented behaviour when two indexes tie on the leading prefix is
-- that "the choice of which index to use is arbitrary" -- and the arbitrary
-- choice was this one. refresh_query_planner_stats() supplies sqlite_stat1 so
-- the choice is made on cost instead, per query.
--
-- Do NOT "simplify" by dropping idx_gn_tenant_scan as a redundant prefix of
-- this index. That is the general SQLite guidance and it is wrong here:
-- measured, dropping it costs the full read 533.8 -> 652.9 ms, because the
-- prefix rule assumes lookup cost and this read is dominated by table locality.
CREATE INDEX IF NOT EXISTS idx_gn_tenant_scan_rank
    ON graph_nodes(tenant_id, scan_id, severity_id DESC, risk_score DESC, label ASC, id ASC);

-- ── Graph edges (one row per edge per scan) ──
CREATE TABLE IF NOT EXISTS graph_edges (
    source_id       TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    relationship    TEXT NOT NULL,
    direction       TEXT DEFAULT 'directed',
    weight          REAL DEFAULT 1.0,
    traversable     INTEGER DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    valid_from      TEXT DEFAULT '',
    valid_to        TEXT DEFAULT NULL,
    confidence      REAL DEFAULT 1.0,
    provenance      TEXT DEFAULT '{}',
    source_scan_id  TEXT DEFAULT '',
    source_run_id   TEXT DEFAULT '',
    evidence        TEXT DEFAULT '{}',
    activity_id     INTEGER DEFAULT 1,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_ge_source ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_ge_target ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_ge_rel ON graph_edges(relationship);
CREATE INDEX IF NOT EXISTS idx_ge_scan ON graph_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan ON graph_edges(tenant_id, scan_id);
-- Frontier lookup for every incremental walk (traverse_subgraph, bfs_paths,
-- impact_of): "which edges touch these node ids, in this snapshot?", asked
-- once per visited node. The single-column idx_ge_source/idx_ge_target cannot
-- serve it -- they carry no tenant/scan prefix, so the planner fell back to
-- idx_ge_tenant_scan and read EVERY edge of the snapshot on EVERY hop, making
-- the walk cost visited x snapshot_edges. These mirror the Postgres store's
-- idx_pg_graph_edges_scan_source / _scan_target.
--
-- The indexes are necessary but NOT sufficient: SQLite will not drive them
-- from a single (source_id IN ... OR target_id IN ...) disjunction, which is
-- why the query is written as a UNION of two endpoint-anchored branches.
-- Together: 7,127us -> 26us per hop on an 80,181-node snapshot. Created here
-- rather than in a migration block because _init_db replays this script on
-- every open, so existing stores pick them up too.
CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan_source ON graph_edges(tenant_id, scan_id, source_id);
CREATE INDEX IF NOT EXISTS idx_ge_tenant_scan_target ON graph_edges(tenant_id, scan_id, target_id);
CREATE INDEX IF NOT EXISTS idx_ge_adjacency_out ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship);
CREATE INDEX IF NOT EXISTS idx_ge_adjacency_in ON graph_edges(tenant_id, scan_id, target_id, source_id, relationship);

-- ── Snapshots ──
CREATE TABLE IF NOT EXISTS graph_snapshots (
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    created_at      TEXT NOT NULL,
    node_count      INTEGER DEFAULT 0,
    edge_count      INTEGER DEFAULT 0,
    risk_summary    TEXT DEFAULT '{}',
    node_type_counts TEXT DEFAULT NULL,
    analysis_status TEXT DEFAULT '{}',
    snapshot_kind   TEXT NOT NULL DEFAULT 'scan' CHECK (snapshot_kind IN ('scan', 'correlation')),
    correlation_id  TEXT DEFAULT NULL,
    evidence_manifest_sha256 TEXT NOT NULL DEFAULT '',
    snapshot_generation TEXT NOT NULL DEFAULT '',
    read_revision TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_gs_recent ON graph_snapshots(tenant_id, created_at DESC);

-- ── Immutable graph correlation requests + monotonic execution state ──
CREATE TABLE IF NOT EXISTS graph_correlation_runs (
    correlation_id  TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    idempotency_key TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
    max_age_hours   INTEGER NOT NULL CHECK (max_age_hours BETWEEN 1 AND 8760),
    allow_stale     INTEGER NOT NULL DEFAULT 0 CHECK (allow_stale IN (0, 1)),
    input_manifest  TEXT NOT NULL DEFAULT '[]',
    result_manifest TEXT NOT NULL DEFAULT '{}',
    manifest_sha256 TEXT NOT NULL DEFAULT '',
    output_scan_id  TEXT NOT NULL DEFAULT '',
    failure_code    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT '',
    completed_at    TEXT NOT NULL DEFAULT '',
    execution_owner TEXT NOT NULL DEFAULT '',
    execution_lease_expires_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (correlation_id, tenant_id),
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_gcr_recent ON graph_correlation_runs(tenant_id, created_at DESC);


-- ── Attack paths (per scan, one row per route occurrence) ──
"""
    + _ATTACK_PATHS_DDL
    + _ATTACK_PATH_INDEXES
    + """
-- ── Snapshot-materialized attack paths (complete ranked set, one row per occurrence) ──
CREATE TABLE IF NOT EXISTS graph_attack_paths (
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    scan_id             TEXT NOT NULL,
    snapshot_generation TEXT NOT NULL DEFAULT '',
    path_key            TEXT NOT NULL,
    path_kind           TEXT NOT NULL,
    derivation_version  INTEGER NOT NULL,
    rank_index          INTEGER NOT NULL,
    source_node         TEXT NOT NULL,
    target_node         TEXT NOT NULL,
    hop_count           INTEGER NOT NULL DEFAULT 0,
    composite_risk      REAL NOT NULL DEFAULT 0.0,
    queue_rank          INTEGER NOT NULL DEFAULT 0,
    severity_rank       INTEGER NOT NULL DEFAULT 0,
    has_credential      INTEGER NOT NULL DEFAULT 0,
    source_type         TEXT NOT NULL DEFAULT '',
    path_json           TEXT NOT NULL,
    computed_at         TEXT NOT NULL,
    PRIMARY KEY (tenant_id, scan_id, path_key)
);
CREATE INDEX IF NOT EXISTS idx_gap_rank ON graph_attack_paths(tenant_id, scan_id, rank_index);
CREATE INDEX IF NOT EXISTS idx_gap_source ON graph_attack_paths(tenant_id, scan_id, source_node, rank_index);
CREATE INDEX IF NOT EXISTS idx_gap_queue ON graph_attack_paths(tenant_id, scan_id, queue_rank);

-- ── Interaction risks (per scan) ──
CREATE TABLE IF NOT EXISTS interaction_risks (
    pattern         TEXT NOT NULL,
    agents          TEXT NOT NULL,
    risk_score      REAL DEFAULT 0.0,
    description     TEXT DEFAULT '',
    owasp_agentic_tag TEXT DEFAULT NULL,
    scan_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_ir_tenant_scan ON interaction_risks(tenant_id, scan_id);

-- ── Schema version ──
CREATE TABLE IF NOT EXISTS graph_schema_version (
    version INTEGER PRIMARY KEY
);

-- ── Retention purge state (single row) ──
CREATE TABLE IF NOT EXISTS graph_retention_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    last_purge_at     TEXT,
    last_purged_count INTEGER DEFAULT 0
);
"""
)


# Tables purged (in FK-safe order) when a graph snapshot ages out of the
# retention window. Ordered children-before-parents so a partial failure never
# leaves orphaned nodes/edges pointing at a deleted snapshot.
_GRAPH_PURGEABLE_TABLES = (
    "graph_attack_paths",
    "attack_paths",
    "interaction_risks",
    "graph_edges",
    "graph_nodes",
    "graph_snapshots",
)


_LEGACY_ATTACK_PATH_COLUMNS = (
    "source_node",
    "target_node",
    "hop_count",
    "composite_risk",
    "summary",
    "path_nodes",
    "path_edges",
    "credential_exposure",
    "tool_exposure",
    "vuln_ids",
    "reachability",
    "reachability_basis",
    "technique_mappings",
    "hop_evidence",
    "analysis",
    "scan_id",
    "tenant_id",
    "computed_at",
)


def _json_list(raw: Any) -> list[Any]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


# Every persisted-path read uses this column list and order on both backends:
# highest risk first, ties broken by the stable route key.
ATTACK_PATH_SELECT = (
    "source_node, target_node, path_nodes, path_edges, composite_risk, summary, credential_exposure, tool_exposure, "
    "vuln_ids, reachability, reachability_basis, technique_mappings, hop_evidence, analysis, finding_ids"
)
ATTACK_PATH_ORDER = "composite_risk DESC, path_key"


def attack_path_from_row(row: sqlite3.Row) -> AttackPath:
    return AttackPath(
        source=row["source_node"],
        target=row["target_node"],
        hops=json.loads(row["path_nodes"]),
        edges=json.loads(row["path_edges"]),
        composite_risk=row["composite_risk"],
        summary=row["summary"] or "",
        credential_exposure=json.loads(row["credential_exposure"]),
        tool_exposure=json.loads(row["tool_exposure"]),
        vuln_ids=json.loads(row["vuln_ids"]),
        reachability=row["reachability"] or "unknown",
        reachability_basis=json.loads(row["reachability_basis"] or "[]"),
        hop_evidence=json.loads(row["hop_evidence"] or "[]"),
        analysis=json.loads(row["analysis"] or "{}"),
        technique_mappings=technique_mappings_from_json(row["technique_mappings"]),
        finding_ids=json.loads(row["finding_ids"] or "[]"),
    )


def upgrade_attack_path_identity(conn: sqlite3.Connection) -> None:
    """Rebuild a pre-occurrence ``attack_paths`` table keyed by route, not endpoints.

    The old key (source, target, scan, tenant) let a second route between the
    same endpoints overwrite the first. SQLite cannot alter a primary key, so
    the table is rebuilt once and every existing row gets its computed key.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(attack_paths)").fetchall()}
    if "path_key" in columns:
        return
    conn.execute("ALTER TABLE attack_paths RENAME TO attack_paths_pre_identity")
    conn.execute(_ATTACK_PATHS_DDL)
    names = ", ".join(_LEGACY_ATTACK_PATH_COLUMNS)
    rows = conn.execute(
        f"SELECT {names} FROM attack_paths_pre_identity ORDER BY tenant_id, scan_id, rowid"  # nosec B608 - static columns
    ).fetchall()
    scopes: dict[tuple[str, str], list[Sequence[Any]]] = {}
    for row in rows:
        scopes.setdefault((row[16], row[15]), []).append(tuple(row))
    upgraded: list[tuple[Any, ...]] = []
    for scoped in scopes.values():
        paths = (AttackPath(source=row[0], target=row[1], hops=_json_list(row[5]), edges=_json_list(row[6])) for row in scoped)
        upgraded.extend((*row, key) for row, (key, _) in zip(scoped, occurrence_path_keys(paths)))
    conn.executemany(
        f"INSERT INTO attack_paths ({names}, path_key) VALUES ({', '.join('?' for _ in range(len(_LEGACY_ATTACK_PATH_COLUMNS) + 1))})",  # nosec B608
        upgraded,
    )
    conn.execute("DROP TABLE attack_paths_pre_identity")
    for statement in filter(None, (part.strip() for part in _ATTACK_PATH_INDEXES.split(";"))):
        conn.execute(statement)


def _graph_retention_days() -> int:
    raw = env_raw("AGENT_BOM_GRAPH_RETENTION_DAYS", str(_DEFAULT_GRAPH_RETENTION_DAYS))
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_GRAPH_RETENTION_DAYS


def normalize_graph_tenant_id(tenant_id: str | None) -> str:
    """Map legacy blank graph tenants into the canonical default bucket."""

    return (tenant_id or "").strip() or DEFAULT_GRAPH_TENANT_ID


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'virtual') AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _read_purge_state(conn: sqlite3.Connection) -> tuple[str | None, int]:
    """Return ``(last_purge_at, last_purged_count)`` for the retention state row."""
    if not _table_exists(conn, "graph_retention_state"):
        return None, 0
    try:
        row = conn.execute("SELECT last_purge_at, last_purged_count FROM graph_retention_state WHERE id = 1").fetchone()
    except sqlite3.Error:
        return None, 0
    if row is None:
        return None, 0
    last_purge_at = row[0]
    last_purged_count = row[1] if row[1] is not None else 0
    return (str(last_purge_at) if last_purge_at is not None else None), int(last_purged_count)


def _record_purge_state(conn: sqlite3.Connection, *, purged_count: int, purged_at: str) -> None:
    conn.execute(
        """
        INSERT INTO graph_retention_state (id, last_purge_at, last_purged_count)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            last_purge_at = excluded.last_purge_at,
            last_purged_count = excluded.last_purged_count
        """,
        (purged_at, int(purged_count)),
    )


def _parse_iso_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp; return ``None`` when unparseable."""
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _batched_rows(rows: Iterable[Sequence[Any]], batch_size: int) -> Iterator[list[Sequence[Any]]]:
    batch: list[Sequence[Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _executemany_batched(
    conn: sqlite3.Connection,
    sql: str,
    rows: Iterable[Sequence[Any]],
    *,
    batch_size: int,
) -> int:
    total = 0
    for batch in _batched_rows(rows, batch_size):
        conn.executemany(sql, batch)
        total += len(batch)
    return total


def normalize_snapshot_kind(snapshot_kind: str) -> str:
    """Validate the immutable snapshot product selected by a graph consumer."""
    normalized = str(snapshot_kind or "").strip().lower()
    if normalized not in GRAPH_SNAPSHOT_KINDS:
        raise ValueError("snapshot_kind must be 'scan' or 'correlation'")
    return normalized


def _digest_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
