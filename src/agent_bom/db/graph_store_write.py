"""Streamed graph snapshot write stages used by ``save_graph_streaming``."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_bom.db.graph_revision import revision_tokens
from agent_bom.db.graph_store_correlation import get_correlation_run
from agent_bom.db.graph_store_schema import _executemany_batched
from agent_bom.graph import (
    AttackPath,
    EntityType,
    InteractionRisk,
    NodeStatus,
    RelationshipType,
    UnifiedEdge,
    UnifiedNode,
)
from agent_bom.graph.analysis import GraphAnalysisStatus, analysis_status_map_to_dict
from agent_bom.graph.correlation import CorrelationRunStatus, validate_correlation_update
from agent_bom.graph.observation_scope import comparable_observation_sql
from agent_bom.graph.severity_floor import counts_as_finding
from agent_bom.graph.snapshot_paths import SNAPSHOT_PATH_COLUMNS, SnapshotPath, snapshot_path_rows


@dataclass
class _SnapshotStats:
    """Incrementally accumulated snapshot stats — mirrors UnifiedGraph.stats().

    ``severity_counts`` only counts truthy finding severities; ``type_counts`` counts
    every node, without a second pass over a fully materialised graph.
    """

    node_count: int = 0
    edge_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    type_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))


def _check_snapshot_writable(conn: sqlite3.Connection, *, tenant: str, scan: str, snapshot_kind: str, correlation_id: str) -> None:
    if snapshot_kind not in {"scan", "correlation"}:
        raise ValueError("snapshot_kind must be 'scan' or 'correlation'")
    if snapshot_kind == "correlation" and correlation_id != scan:
        raise ValueError("correlation snapshot ID must equal correlation_id")
    existing_snapshot = conn.execute(
        "SELECT snapshot_kind FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
        (tenant, scan),
    ).fetchone()
    if existing_snapshot is not None:
        if str(existing_snapshot["snapshot_kind"] or "scan") == "correlation":
            raise ValueError("correlation snapshot is immutable")
        if snapshot_kind == "correlation":
            raise ValueError("correlation snapshot ID collides with an existing scan")
    reserved_correlation = conn.execute(
        "SELECT correlation_id FROM graph_correlation_runs WHERE tenant_id = ? AND correlation_id = ?",
        (tenant, scan),
    ).fetchone()
    if reserved_correlation is not None and snapshot_kind != "correlation":
        raise ValueError("correlation output identifier is reserved")


def _clear_snapshot_rows(conn: sqlite3.Connection, *, tenant: str, scan: str) -> None:
    # A scan id is one complete snapshot. Retries/replays must replace that
    # snapshot atomically; upserts alone would retain rows absent from the
    # retried producer and make graph_snapshots counts contradict graph rows.
    # The first DELETE also takes SQLite's write lock, serializing concurrent
    # writers before any streamed batch is consumed.
    for table in ("graph_attack_paths", "attack_paths", "interaction_risks", "graph_edges", "graph_nodes", "graph_snapshots"):
        conn.execute(
            f"DELETE FROM {table} WHERE tenant_id = ? AND scan_id = ?",  # nosec B608 - static table list
            (tenant, scan),
        )


def _node_rows(nodes: Iterable[UnifiedNode], stats: _SnapshotStats, *, scan: str, tenant: str) -> Iterator[tuple[Any, ...]]:
    for node in nodes:
        stats.node_count += 1
        et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
        stats.type_counts[et] += 1
        if node.severity and counts_as_finding(entity_type=et, node_id=node.id):
            stats.severity_counts[node.severity] += 1
        yield (
            node.id,
            et,
            node.label,
            node.category_uid,
            node.class_uid,
            node.type_uid,
            node.status.value if isinstance(node.status, NodeStatus) else node.status,
            node.risk_score,
            node.severity,
            node.severity_id,
            node.first_seen,
            node.last_seen,
            json.dumps(node.attributes, default=str),
            json.dumps(node.compliance_tags),
            json.dumps(node.data_sources),
            json.dumps(node.dimensions.to_dict()),
            scan,
            tenant,
        )


def _write_nodes(
    conn: sqlite3.Connection, nodes: Iterable[UnifiedNode], stats: _SnapshotStats, *, scan: str, tenant: str, batch_size: int
) -> None:
    _executemany_batched(
        conn,
        """\
        INSERT OR REPLACE INTO graph_nodes (
            id, entity_type, label, category_uid, class_uid, type_uid,
            status, risk_score, severity, severity_id,
            first_seen, last_seen, attributes, compliance_tags,
            data_sources, dimensions, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        _node_rows(nodes, stats, scan=scan, tenant=tenant),
        batch_size=batch_size,
    )


def _edge_rows(edges: Iterable[UnifiedEdge], stats: _SnapshotStats, *, scan: str, tenant: str, now: str) -> Iterator[tuple[Any, ...]]:
    for edge in edges:
        stats.edge_count += 1
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        # A snapshot may record a future grant or observation. Backdating
        # its start changes temporal traversal and correlation receipts.
        valid_from = edge.valid_from or edge.first_seen or now
        yield (
            edge.source,
            edge.target,
            rel,
            edge.direction,
            edge.weight,
            1 if edge.traversable else 0,
            edge.first_seen,
            edge.last_seen,
            valid_from,
            edge.valid_to,
            edge.confidence,
            json.dumps(edge.provenance, default=str),
            edge.source_scan_id or scan,
            edge.source_run_id,
            json.dumps(edge.evidence, default=str),
            edge.activity_id,
            scan,
            tenant,
        )


def _write_edges(
    conn: sqlite3.Connection,
    edges: Iterable[UnifiedEdge],
    stats: _SnapshotStats,
    *,
    scan: str,
    tenant: str,
    now: str,
    batch_size: int,
) -> None:
    _executemany_batched(
        conn,
        """\
        INSERT OR REPLACE INTO graph_edges (
            source_id, target_id, relationship, direction, weight,
            traversable, first_seen, last_seen, valid_from, valid_to,
            confidence, provenance, source_scan_id, source_run_id, evidence,
            activity_id, scan_id, tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        _edge_rows(edges, stats, scan=scan, tenant=tenant, now=now),
        batch_size=batch_size,
    )


def _carry_forward_edge_continuity(conn: sqlite3.Connection, *, previous_scan: str, scan: str, tenant: str) -> None:
    # Reconcile temporal continuity in SQL. The prior implementation loaded
    # every previous edge into a Python dict + set, making the supposedly
    # streamed path retain O(previous-edge-count) heap. Exact-key correlated
    # lookups use graph_edges' primary key and keep Python memory batch-sized.
    scope_predicate = comparable_observation_sql(dialect="sqlite", previous="previous", current="current")
    conn.execute(
        f"""
        UPDATE graph_edges AS current
        SET first_seen = COALESCE(
                (
                    SELECT NULLIF(previous.first_seen, '')
                    FROM graph_edges AS previous
                    WHERE previous.source_id = current.source_id
                      AND previous.target_id = current.target_id
                      AND previous.relationship = current.relationship
                      AND previous.scan_id = ?
                      AND previous.tenant_id = ?
                ),
                current.first_seen
            ),
            valid_from = COALESCE(
                (
                    SELECT NULLIF(previous.valid_from, '')
                    FROM graph_edges AS previous
                    WHERE previous.source_id = current.source_id
                      AND previous.target_id = current.target_id
                      AND previous.relationship = current.relationship
                      AND previous.scan_id = ?
                      AND previous.tenant_id = ?
                ),
                (
                    SELECT NULLIF(previous.first_seen, '')
                    FROM graph_edges AS previous
                    WHERE previous.source_id = current.source_id
                      AND previous.target_id = current.target_id
                      AND previous.relationship = current.relationship
                      AND previous.scan_id = ?
                      AND previous.tenant_id = ?
                ),
                current.valid_from
            )
        WHERE current.scan_id = ?
          AND current.tenant_id = ?
          AND EXISTS (
                SELECT 1
                FROM graph_edges AS previous
                WHERE previous.source_id = current.source_id
                  AND previous.target_id = current.target_id
                  AND previous.relationship = current.relationship
                  AND previous.scan_id = ?
                  AND previous.tenant_id = ?
                  AND (previous.valid_to IS NULL OR previous.valid_to = '')
                  AND {scope_predicate}
          )
        """,  # nosec B608 - static aliases and internally generated SQL predicates
        (previous_scan, tenant, previous_scan, tenant, previous_scan, tenant, scan, tenant, previous_scan, tenant),
    )


def _write_attack_paths(conn: sqlite3.Connection, attack_paths: Iterable[AttackPath], *, scan: str, tenant: str, now: str) -> int:
    attack_path_count = 0
    for ap in attack_paths:
        attack_path_count += 1
        conn.execute(
            """\
            INSERT OR REPLACE INTO attack_paths (
                source_node, target_node, hop_count, composite_risk,
                summary, path_nodes, path_edges, credential_exposure,
                tool_exposure, vuln_ids, reachability, reachability_basis,
                technique_mappings, hop_evidence, analysis, scan_id, tenant_id, computed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ap.source,
                ap.target,
                len(ap.hops),
                ap.composite_risk,
                ap.summary,
                json.dumps(ap.hops),
                json.dumps(ap.edges),
                json.dumps(ap.credential_exposure),
                json.dumps(ap.tool_exposure),
                json.dumps(ap.vuln_ids),
                ap.reachability,
                json.dumps(ap.reachability_basis),
                json.dumps([m.to_dict() for m in ap.technique_mappings]),
                json.dumps(ap.hop_evidence, sort_keys=True),
                json.dumps(ap.analysis, sort_keys=True),
                scan,
                tenant,
                now,
            ),
        )
    return attack_path_count


def _write_snapshot_paths(conn: sqlite3.Connection, rows: Sequence[SnapshotPath], *, scan: str, tenant: str, now: str) -> None:
    generation = conn.execute(
        "SELECT snapshot_generation FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
        (tenant, scan),
    ).fetchone()[0]
    placeholders = ", ".join("?" for _ in SNAPSHOT_PATH_COLUMNS)
    conn.executemany(
        f"INSERT INTO graph_attack_paths ({', '.join(SNAPSHOT_PATH_COLUMNS)}) VALUES ({placeholders})",  # nosec B608 - static columns
        snapshot_path_rows(rows, tenant=tenant, scan=scan, generation=generation, now=now),
    )


def _write_interaction_risks(conn: sqlite3.Connection, interaction_risks: Iterable[InteractionRisk], *, scan: str, tenant: str) -> None:
    for ir in interaction_risks:
        conn.execute(
            """\
            INSERT OR REPLACE INTO interaction_risks (
                pattern, agents, risk_score, description,
                owasp_agentic_tag, scan_id, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ir.pattern, json.dumps(sorted(ir.agents)), ir.risk_score, ir.description, ir.owasp_agentic_tag, scan, tenant),
        )


def _write_snapshot_row(
    conn: sqlite3.Connection,
    stats: _SnapshotStats,
    *,
    scan: str,
    tenant: str,
    now: str,
    analysis_status: Mapping[str, GraphAnalysisStatus] | None,
    snapshot_kind: str,
    correlation_id: str,
    evidence_manifest_sha256: str,
    write_generation: str,
) -> None:
    # Materialise the entity-type and severity breakdowns alongside the node/edge
    # totals so inventory/summary serves them from this row instead of running a
    # GROUP BY over every node per request (O(N) → O(1)). ``risk_summary`` already
    # carries the severity breakdown; ``node_type_counts`` adds the entity types.
    conn.execute(
        """
        INSERT OR REPLACE INTO graph_snapshots
            (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary,
             node_type_counts, analysis_status, snapshot_kind, correlation_id,
             evidence_manifest_sha256, snapshot_generation, read_revision)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan,
            tenant,
            now,
            stats.node_count,
            stats.edge_count,
            json.dumps(dict(stats.severity_counts)),
            json.dumps(dict(stats.type_counts)),
            json.dumps(analysis_status_map_to_dict(analysis_status or {})),
            snapshot_kind,
            correlation_id or None,
            evidence_manifest_sha256,
            *revision_tokens(write_generation),
        ),
    )


def _complete_correlation_run_atomically(
    conn: sqlite3.Connection,
    *,
    tenant: str,
    scan: str,
    correlation_id: str,
    evidence_manifest_sha256: str,
    correlation_result_manifest: Mapping[str, Any],
    completed_at: str,
    execution_owner: str,
) -> None:
    existing = get_correlation_run(conn, tenant_id=tenant, correlation_id=correlation_id)
    if existing is None:
        raise KeyError("correlation run not found")
    resolved_hash, resolved_result, resolved_output, resolved_failure = validate_correlation_update(
        existing,
        status=CorrelationRunStatus.COMPLETE,
        manifest_sha256=evidence_manifest_sha256,
        result_manifest=correlation_result_manifest,
        output_scan_id=scan,
    )
    conn.execute(
        """
        UPDATE graph_correlation_runs
        SET status = ?, manifest_sha256 = ?, result_manifest = ?, output_scan_id = ?,
            failure_code = ?, completed_at = ?
        WHERE tenant_id = ? AND correlation_id = ? AND status = ?
          AND (? = '' OR execution_owner = ?)
        """,
        (
            CorrelationRunStatus.COMPLETE.value,
            resolved_hash,
            json.dumps(resolved_result, sort_keys=True, separators=(",", ":")),
            resolved_output,
            resolved_failure,
            completed_at,
            tenant,
            correlation_id,
            existing.status.value,
            execution_owner,
            execution_owner,
        ),
    )
    if conn.execute("SELECT changes()").fetchone()[0] != 1:
        raise RuntimeError("correlation run changed during atomic completion")
