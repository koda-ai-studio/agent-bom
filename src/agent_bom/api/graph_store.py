"""Unified graph store backends for API persistence and querying.

Graph reads and writes share the control plane backend selection. SQLite is
the local default; Postgres provides the same tenant-scoped contract.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.api import graph_search_rank as search_rank
from agent_bom.api.graph_store_pages import SQLiteGraphPagesMixin
from agent_bom.api.graph_store_support import _API_GRAPH_TENANT_TABLE_KEYS as _API_GRAPH_TENANT_TABLE_KEYS
from agent_bom.api.graph_store_support import _CREATE_PRESET_TABLE_SQLITE as _CREATE_PRESET_TABLE_SQLITE
from agent_bom.api.graph_store_support import _DYNAMIC_RELATIONSHIP_VALUES as _DYNAMIC_RELATIONSHIP_VALUES
from agent_bom.api.graph_store_support import _FINDING_ENTITY_TYPE_VALUES as _FINDING_ENTITY_TYPE_VALUES
from agent_bom.api.graph_store_support import MAX_NODE_PAGE_OFFSET as MAX_NODE_PAGE_OFFSET
from agent_bom.api.graph_store_support import SQLITE_INVENTORY_SEARCH_CLAUSE
from agent_bom.api.graph_store_support import _assert_offset_within_cap as _assert_offset_within_cap
from agent_bom.api.graph_store_support import _attach_sibling_relationships as _attach_sibling_relationships
from agent_bom.api.graph_store_support import _drilldown_subtree_budget as _drilldown_subtree_budget
from agent_bom.api.graph_store_support import _escape_like_query as _escape_like_query
from agent_bom.api.graph_store_support import _node_sort_key as _node_sort_key
from agent_bom.api.graph_store_support import _typed_containment_subtree as _typed_containment_subtree
from agent_bom.api.graph_store_support import _unsupported_traversal_errors as _unsupported_traversal_errors
from agent_bom.api.graph_store_support import decode_graph_cursor as decode_graph_cursor
from agent_bom.api.graph_store_support import encode_graph_cursor as encode_graph_cursor
from agent_bom.api.storage.sqlite_graph_search import scoped_search_expression
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import (
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.analysis import analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.graph.completeness import (
    COMPLIANCE_NODE_BUDGET,
    graph_completeness,
)
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol
from agent_bom.graph.severity_floor import FINDING_SEVERITY_SQLITE, severity_floor_sql


def containment_drilldown_graph(
    store: GraphStoreProtocol,
    *,
    node_id: str,
    tenant_id: str = "",
    scan_id: str = "",
    node_budget: int | None = None,
) -> UnifiedGraph:
    """Fetch only the containment subtree a roll-up drill-down reads.

    ``drill_down`` answers one container's direct children, but its aggregates
    (descendant counts, severity histogram, exposure flags) cover each child's
    whole subtree. The subtree under ``node_id`` is therefore the exact part of
    the estate the answer depends on — and the only part worth fetching.

    Loading the full snapshot instead made a twenty-row answer cost time linear
    in estate size. Measured on SQLite, drilling into one application whose
    answer is twenty children either way:

        snapshot     full load        containment walk
         5,065 nodes    55.1 ms          1.2 ms  (21 nodes read)
        20,046 nodes   270.2 ms          1.4 ms  (21 nodes read)
        40,091 nodes   580.5 ms          1.2 ms  (21 nodes read)
        80,181 nodes 1,141.6 ms          1.2 ms  (21 nodes read)

    The walk is ``traverse_subgraph``, the incremental primitive that already
    made ``impact_of`` sublinear, rather than a new store method — every backend
    that can traverse gets this without a protocol change.

    **The budget is a dispatch threshold, not a cap on the answer.** A container
    whose subtree does not fit falls back to the full load and returns exactly
    what it would have returned before. Truncating instead would have been both
    dishonest-looking and pointless: at the root of the tree the subtree *is* the
    estate, so the walk is strictly more expensive than one bulk read, and every
    ``descendant_count`` in the response would silently become a floor. The cost
    of that choice is the wasted partial walk before a fallback — measured at
    +44 ms on an 80,181-node root drill that already took 1,189 ms. The fast path
    is for the drill targets below the top, which is where drill-down goes.

    This is why ``traverse_subgraph`` reporting its own truncation matters here:
    the flag is what selects the fallback. A walk that under-reported itself as
    complete would ship bounded aggregates as if they were totals.

    ``max_depth`` is set to the node budget deliberately: a walk of depth *d*
    visits at least *d + 1* distinct nodes, so the node budget — which reports
    itself as truncation — always binds first. ``max_depth`` cuts a walk
    *without* setting that flag, so a depth-bound walk would return a short
    subtree that looks complete, and the fallback would never fire.

    A backend that cannot traverse incrementally (the experimental Neptune
    adapter implements only part of the protocol) takes the same fallback, so
    its answer is unchanged rather than a 501.
    """
    from agent_bom.graph.rollup import ROLLUP_RELATIONSHIPS, ROLLUP_SUBTREE_RELATIONSHIP_TYPES

    def _full_load() -> UnifiedGraph:
        return store.load_graph(
            tenant_id=tenant_id,
            scan_id=scan_id,
            relationship_types=ROLLUP_RELATIONSHIPS,
        )

    budget = node_budget if node_budget is not None else _drilldown_subtree_budget()
    try:
        graph, _depths, truncated = store.traverse_subgraph(
            tenant_id=tenant_id,
            scan_id=scan_id,
            roots=[node_id],
            direction="forward",
            max_depth=budget,
            max_nodes=budget,
            # Every visited node also matches on the edge that reached it, so the
            # edge budget must clear the node budget or it, not the node budget,
            # becomes the binding limit.
            max_edges=budget * 4,
            relationship_types=set(ROLLUP_SUBTREE_RELATIONSHIP_TYPES),
            include_roots=True,
        )
    except _unsupported_traversal_errors():
        return _full_load()
    if truncated:
        return _full_load()
    graph = _typed_containment_subtree(graph, node_id)
    _attach_sibling_relationships(store, graph, tenant_id=tenant_id, scan_id=scan_id)
    return graph


class SQLiteGraphStore(SQLiteGraphPagesMixin):
    """SQLite-backed graph store wrapper around the low-level graph DB helpers."""

    def _frontier_edge_query(
        self,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> tuple[str, list[Any]]:
        """Build the per-hop "edges touching these nodes" query, and its parameters.

        Written as a UNION of two endpoint-anchored branches rather than the
        obvious ``source_id IN (...) OR target_id IN (...)`` disjunction. SQLite
        cannot drive a single index from that disjunction: it settles on
        ``idx_ge_tenant_scan`` and reads every edge in the snapshot, once per
        node the walk visits, making traversal cost visited x snapshot_edges.
        Split into two branches, each is an index seek against
        ``idx_ge_tenant_scan_source`` / ``idx_ge_tenant_scan_target``, so a hop
        costs its own degree.

        Both halves are load-bearing: the disjunction ignores those indexes even
        when they exist, and the UNION falls back to a full snapshot scan when
        they do not. Neither relies on ``sqlite_stat1``, which a freshly written
        customer database does not have.

        ``ORDER BY rowid`` reproduces the row order the scan happened to yield
        (index entries for one snapshot are ordered by rowid, i.e. insertion
        order), so ``discovery_order``, ``parent_by_node`` and every path built
        from them are unchanged — and are now pinned to insertion order outright
        instead of inherited from whichever plan the query planner picked.
        """
        placeholders = ",".join("?" for _ in frontier)
        # Sorted so the emitted SQL and parameters are deterministic across runs.
        ordered_frontier = sorted(frontier)
        shared: list[str] = []
        shared_params: list[Any] = []
        if traversable_only:
            shared.append("traversable = 1")
        if relationship_types:
            rel_values = sorted(rel.value if isinstance(rel, RelationshipType) else str(rel) for rel in relationship_types)
            shared.append(f"relationship IN ({','.join('?' for _ in rel_values)})")
            shared_params.extend(rel_values)
        if static_only:
            shared.append(f"relationship NOT IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
            shared_params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        if dynamic_only:
            shared.append(f"relationship IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
            shared_params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        shared_sql = ("".join(f" AND {clause}" for clause in shared)) if shared else ""

        def branch(column: str) -> str:
            # nosec B608 - every interpolated fragment is built in this function
            # and none is caller-supplied: ``column`` is one of two string
            # literals at the call sites below, and ``placeholders``/
            # ``shared_sql`` contribute only ``?`` markers. Values travel in
            # ``params``.
            return f"SELECT rowid FROM graph_edges WHERE tenant_id = ? AND scan_id = ? AND {column} IN ({placeholders}){shared_sql}"  # nosec B608

        params: list[Any] = [
            tenant_id,
            scan_id,
            *ordered_frontier,
            *shared_params,
            tenant_id,
            scan_id,
            *ordered_frontier,
            *shared_params,
        ]
        sql = f"""
            SELECT *
            FROM graph_edges
            WHERE rowid IN (
                {branch("source_id")}
                UNION
                {branch("target_id")}
            )
            ORDER BY rowid
            """  # nosec B608 - clause fragments and placeholders are generated internally
        return sql, params

    def _walk_graph(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        roots: list[str],
        direction: str,
        max_depth: int,
        max_nodes: int,
        max_edges: int,
        deadline_monotonic: float | None,
        traversable_only: bool,
        relationship_types: set[RelationshipType] | None,
        static_only: bool,
        dynamic_only: bool,
        include_roots: bool,
    ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], UnifiedEdge], dict[str, str], list[str], bool, bool]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
        if not effective_scan_id:
            return scan_id, "", set(), {}, {}, {}, [], False, False

        existing_roots = {node.id for node in self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(roots))}
        visited: set[str] = set()
        depth_by_node: dict[str, int] = {}
        traversed_edges: dict[tuple[str, str, str], UnifiedEdge] = {}
        parent_by_node: dict[str, str] = {}
        discovery_order: list[str] = []
        truncated = False
        depth_limited = False
        edge_count = 0

        def _neighbors(node_id: str) -> list[str]:
            found: list[str] = []
            for row in self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={node_id},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
            ):
                edge = self._edge_from_row(row)
                if direction in {"forward", "both"}:
                    if edge.source == node_id:
                        found.append(edge.target)
                    elif edge.is_bidirectional and edge.target == node_id:
                        found.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == node_id:
                        found.append(edge.source)
                    elif edge.is_bidirectional and edge.source == node_id:
                        found.append(edge.target)
            return found

        queue: list[tuple[str, int]] = []
        for root in roots:
            if root not in existing_roots:
                continue
            queue.append((root, 0))
            depth_by_node[root] = 0
            if include_roots:
                visited.add(root)

        index = 0
        while index < len(queue):
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                truncated = True
                break
            current, depth = queue[index]
            index += 1
            if depth >= max_depth:
                # Frontier node: only a *demonstrably* unwalked neighbour makes
                # this an incomplete answer. Costs one edge lookup per frontier
                # node, and only until the first one that leaves work behind.
                if not depth_limited and any(neighbor not in visited for neighbor in _neighbors(current)):
                    depth_limited = True
                continue
            for row in self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={current},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
            ):
                edge = self._edge_from_row(row)
                candidates: list[str] = []
                if direction in {"forward", "both"}:
                    if edge.source == current:
                        candidates.append(edge.target)
                    elif edge.is_bidirectional and edge.target == current:
                        candidates.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == current:
                        candidates.append(edge.source)
                    elif edge.is_bidirectional and edge.source == current:
                        candidates.append(edge.target)
                if not candidates:
                    continue

                edge_count += 1
                if edge_count > max_edges:
                    truncated = True
                    break

                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
                traversed_edges.setdefault((edge.source, edge.target, rel), edge)

                for neighbor in candidates:
                    if neighbor in visited:
                        continue
                    if len(visited) >= max_nodes:
                        truncated = True
                        continue
                    visited.add(neighbor)
                    depth_by_node[neighbor] = depth + 1
                    parent_by_node.setdefault(neighbor, current)
                    discovery_order.append(neighbor)
                    queue.append((neighbor, depth + 1))
            if truncated and (edge_count > max_edges or (deadline_monotonic is not None and time.monotonic() >= deadline_monotonic)):
                break

        if include_roots:
            visited.update(existing_roots)

        return (
            effective_scan_id,
            created_at,
            visited,
            depth_by_node,
            traversed_edges,
            parent_by_node,
            discovery_order,
            truncated,
            depth_limited,
        )

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        # The same budget Postgres applies. This read used to be unbounded here
        # and bounded there, so the two backends answered the same leadership
        # question from different amounts of the estate — and only one of them
        # said so.
        compliance_node_budget = COMPLIANCE_NODE_BUDGET
        empty = {
            "scan_id": scan_id,
            "framework_count": 0,
            "total_tagged_findings": 0,
            "frameworks": {},
            "completeness": {
                **graph_completeness(returned=0),
                "node_budget": compliance_node_budget,
            },
        }
        conn = self._open_ro_conn()
        if conn is None:
            return empty
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return empty

            rows = conn.execute(
                """
                SELECT id, entity_type, severity, compliance_tags
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND json_array_length(compliance_tags) > 0
                ORDER BY id ASC
                LIMIT ?
                """,
                [tenant_id, effective_scan_id, compliance_node_budget + 1],
            ).fetchall()
            truncated = len(rows) > compliance_node_budget
            rows = rows[:compliance_node_budget]

            framework_filter = framework.upper()
            framework_stats: dict[str, dict[str, Any]] = defaultdict(
                lambda: {
                    "total_findings": 0,
                    "by_severity": defaultdict(int),
                    "by_entity_type": defaultdict(int),
                    "tags": set(),
                    "node_ids": [],
                }
            )

            for row in rows:
                tags = json.loads(row["compliance_tags"])
                if not tags:
                    continue
                for tag in tags:
                    prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
                    if framework_filter and framework_filter != prefix:
                        continue
                    stats = framework_stats[prefix]
                    stats["total_findings"] += 1
                    stats["by_severity"][row["severity"] or "unknown"] += 1
                    stats["by_entity_type"][row["entity_type"]] += 1
                    stats["tags"].add(tag)
                    if row["id"] not in stats["node_ids"]:
                        stats["node_ids"].append(row["id"])

            frameworks: dict[str, Any] = {}
            for name, stats in sorted(framework_stats.items()):
                frameworks[name] = {
                    "total_findings": stats["total_findings"],
                    "by_severity": dict(stats["by_severity"]),
                    "by_entity_type": dict(stats["by_entity_type"]),
                    "tags": sorted(stats["tags"]),
                    "node_count": len(stats["node_ids"]),
                    "node_ids": stats["node_ids"][:100],
                }

            return {
                "scan_id": effective_scan_id,
                "framework_count": len(frameworks),
                "total_tagged_findings": sum(stats["total_findings"] for stats in frameworks.values()),
                "frameworks": frameworks,
                "completeness": {
                    **graph_completeness(
                        returned=len(rows),
                        truncated=truncated,
                        reason="node_budget" if truncated else "",
                    ),
                    "node_budget": compliance_node_budget,
                },
            }
        finally:
            conn.close()

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "node_types": {},
                "severity_counts": {},
                "relationship_types": {},
                "attack_path_count": 0,
                "interaction_risk_count": 0,
                "max_attack_path_risk": 0.0,
                "highest_interaction_risk": 0.0,
                "analysis_status": {},
            }
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return {
                    "total_nodes": 0,
                    "total_edges": 0,
                    "node_types": {},
                    "severity_counts": {},
                    "relationship_types": {},
                    "attack_path_count": 0,
                    "interaction_risk_count": 0,
                    "max_attack_path_risk": 0.0,
                    "highest_interaction_risk": 0.0,
                    "analysis_status": {},
                }

            analysis_row = conn.execute(
                "SELECT analysis_status FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
                (effective_scan_id, tenant_id),
            ).fetchone()
            analysis_status = analysis_status_map_to_dict(
                analysis_status_map_from_dict(json.loads((analysis_row[0] if analysis_row else "{}") or "{}"))
            )

            node_where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                node_where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(min_severity_rank)
            if sev_sql:
                node_where.append(sev_sql)
                params.extend(sev_params)
            where_sql = " AND ".join(node_where)

            # Unfiltered node/edge totals AND the entity-type / severity breakdowns
            # are materialised on the snapshot row at write time. Re-deriving them
            # here re-scans graph_nodes with two GROUP BYs (1-2s at 500k-1M nodes)
            # plus a double id-membership edge subquery, so read the stored values
            # and only fall back to the live queries when the snapshot row is missing
            # or the cached breakdown was never populated (older snapshots). Any
            # active entity-type or severity filter narrows the set, so the recompute
            # path still runs.
            filters_active = bool(entity_types) or bool(min_severity_rank)
            stored_node_count: int | None = None
            stored_edge_count: int | None = None
            cached_node_types: dict[str, int] | None = None
            cached_severity_counts: dict[str, int] | None = None
            if not filters_active:
                snap_row = conn.execute(
                    "SELECT node_count, edge_count, risk_summary, node_type_counts "
                    "FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
                    (effective_scan_id, tenant_id),
                ).fetchone()
                if snap_row is not None:
                    stored_node_count = snap_row[0] if snap_row[0] is not None else None
                    stored_edge_count = snap_row[1] if snap_row[1] is not None else None
                    # node_type_counts is NULL for snapshots written before the
                    # breakdown was materialised — fall back to the live GROUP BY
                    # for those. risk_summary already carries the severity counts.
                    if snap_row[3] is not None:
                        cached_node_types = {str(k): int(v) for k, v in json.loads(snap_row[3]).items()}
                        cached_severity_counts = {str(k): int(v) for k, v in json.loads(snap_row[2] or "{}").items() if k}

            if stored_node_count is not None:
                total_nodes = stored_node_count
            else:
                total_nodes = conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
            if cached_node_types is not None:
                node_types = cached_node_types
            else:
                node_type_rows = conn.execute(
                    f"SELECT entity_type, COUNT(*) FROM graph_nodes WHERE {where_sql} GROUP BY entity_type",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchall()
                node_types = {str(row[0]): int(row[1]) for row in node_type_rows}
            if cached_severity_counts is not None:
                severity_counts = cached_severity_counts
            else:
                severity_rows = conn.execute(
                    f"SELECT severity, COUNT(*) FROM graph_nodes WHERE {where_sql} AND {FINDING_SEVERITY_SQLITE[0]} GROUP BY severity",  # nosec B608 - where_sql is built from static clause fragments
                    [*params, *FINDING_SEVERITY_SQLITE[1]],
                ).fetchall()
                severity_counts = {str(row[0]): int(row[1]) for row in severity_rows}
            if stored_edge_count is not None:
                total_edges = stored_edge_count
            else:
                total_edges = conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ?
                      AND EXISTS (SELECT 1 FROM graph_nodes WHERE id = graph_edges.source_id AND {where_sql})
                      AND EXISTS (SELECT 1 FROM graph_nodes WHERE id = graph_edges.target_id AND {where_sql})
                    """,  # nosec B608 - where_sql is built from static clause fragments
                    [tenant_id, effective_scan_id, *params, *params],
                ).fetchone()[0]
            rel_rows = conn.execute(
                f"""
                SELECT relationship, COUNT(*)
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND EXISTS (SELECT 1 FROM graph_nodes WHERE id = graph_edges.source_id AND {where_sql})
                  AND EXISTS (SELECT 1 FROM graph_nodes WHERE id = graph_edges.target_id AND {where_sql})
                GROUP BY relationship
                """,  # nosec B608 - where_sql is built from static clause fragments
                [tenant_id, effective_scan_id, *params, *params],
            ).fetchall()
            attack_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(composite_risk), 0.0) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            interaction_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(risk_score), 0.0) FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            return {
                "total_nodes": int(total_nodes or 0),
                "total_edges": int(total_edges or 0),
                "node_types": node_types,
                "severity_counts": severity_counts,
                "relationship_types": {str(row[0]): int(row[1]) for row in rel_rows},
                "attack_path_count": int((attack_row[0] if attack_row else 0) or 0),
                "interaction_risk_count": int((interaction_row[0] if interaction_row else 0) or 0),
                "max_attack_path_risk": float((attack_row[1] if attack_row else 0.0) or 0.0),
                "highest_interaction_risk": float((interaction_row[1] if interaction_row else 0.0) or 0.0),
                "analysis_status": analysis_status,
            }
        finally:
            conn.close()

    def query_inventory(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        asset_entity_types: set[str],
        entity_types: set[str] | None = None,
        search: str = "",
        environment: str = "",
        provider: str = "",
        source: str = "",
        severity: str = "",
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Query exact inventory rows and whole-query facets in native SQL.

        The snapshot is resolved once and every count, facet, row, relationship,
        and finding summary is evaluated against that immutable tenant-scoped
        snapshot. Facets are self-excluding: each bucket honors every active
        filter except its own dimension.
        """
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return self._empty_inventory_result(scan_id="")
        try:
            # Keep facets, page rows and related evidence in one read snapshot,
            # including when a collector replaces the same scan concurrently.
            conn.execute("BEGIN")
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return self._empty_inventory_result(scan_id="")

            asset_types = sorted(asset_entity_types)
            asset_placeholders = ",".join("?" for _ in asset_types)
            finding_types = sorted(_FINDING_ENTITY_TYPE_VALUES)
            finding_placeholders = ",".join("?" for _ in finding_types)

            def inventory_cte(*, facets: bool = False) -> str:
                # Each facet scans the same qualified assets. Materialize this
                # narrow projection once instead of decoding node JSON per facet.
                projection = "n.id, n.entity_type, n.label, n.attributes, n.data_sources" if facets else "n.*"
                materialized = "MATERIALIZED" if facets and sqlite3.sqlite_version_info >= (3, 35, 0) else ""
                return f"""
                WITH finding_links AS (
                    SELECT e.source_id AS asset_id, f.severity_id
                    FROM graph_edges e
                    JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.target_id
                    WHERE e.tenant_id = ? AND e.scan_id = ? AND f.entity_type IN ({finding_placeholders})
                    UNION ALL
                    SELECT e.target_id AS asset_id, f.severity_id
                    FROM graph_edges e
                    JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.source_id
                    WHERE e.tenant_id = ? AND e.scan_id = ? AND f.entity_type IN ({finding_placeholders})
                ), finding_rollup AS (
                    SELECT asset_id, MAX(COALESCE(severity_id, 0)) AS finding_severity_rank
                    FROM finding_links GROUP BY asset_id
                ), assets_raw AS (
                    SELECT {projection},
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.environment'),
                                                  json_extract(n.attributes, '$.environment'), '')), '') AS inventory_environment,
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.cloud_provider'),
                                                  json_extract(n.attributes, '$.provider'),
                                                  json_extract(n.attributes, '$.cloud_provider'), '')), '') AS inventory_provider,
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.ecosystem'),
                                                  json_extract(n.attributes, '$.ecosystem'), '')), '') AS inventory_ecosystem,
                           finding_rollup.finding_severity_rank
                    FROM graph_nodes n
                    LEFT JOIN finding_rollup ON finding_rollup.asset_id = n.id
                    WHERE n.tenant_id = ? AND n.scan_id = ?
                      AND n.entity_type IN ({asset_placeholders})
                ), assets AS {materialized} (
                    SELECT *, CASE finding_severity_rank
                        WHEN 5 THEN 'critical' WHEN 4 THEN 'high'
                        WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'info'
                        ELSE NULL END AS finding_severity
                    FROM assets_raw
                )
            """  # nosec B608 - static projection/hint; all type and scope values are bound

            cte_params: list[Any] = [
                tenant_id,
                effective_scan_id,
                *finding_types,
                tenant_id,
                effective_scan_id,
                *finding_types,
                tenant_id,
                effective_scan_id,
                *asset_types,
            ]

            normalized = {
                "environment": environment.strip().lower(),
                "provider": provider.strip().lower(),
                "source": source.strip().lower(),
                "severity": severity.strip().lower(),
            }

            def filtered_where(*, exclude: str = "") -> tuple[str, list[Any]]:
                clauses: list[str] = []
                params: list[Any] = []
                if entity_types and exclude != "type":
                    values = sorted(entity_types)
                    clauses.append(f"entity_type IN ({','.join('?' for _ in values)})")
                    params.extend(values)
                if search.strip():
                    clauses.append(SQLITE_INVENTORY_SEARCH_CLAUSE)
                    token = f"%{_escape_like_query(search.strip().lower())}%"
                    params.extend([token, token])
                if normalized["environment"] and exclude != "environment":
                    clauses.append("inventory_environment = ?")
                    params.append(normalized["environment"])
                if normalized["provider"] and exclude != "provider":
                    clauses.append("inventory_provider = ?")
                    params.append(normalized["provider"])
                if normalized["source"] and exclude != "source":
                    clauses.append("EXISTS (SELECT 1 FROM json_each(assets.data_sources) src WHERE LOWER(src.value) = ?)")
                    params.append(normalized["source"])
                if normalized["severity"] and exclude != "severity":
                    clauses.append("finding_severity = ?")
                    params.append(normalized["severity"])
                if min_severity_rank and exclude != "severity":
                    clauses.append("COALESCE(finding_severity_rank, 0) >= ?")
                    params.append(min_severity_rank)
                return (" AND ".join(clauses) if clauses else "1 = 1"), params

            where_sql, where_params = filtered_where()
            facet_sql = [
                f"SELECT '__total__' AS facet, NULL AS value, COUNT(*) AS count FROM assets WHERE {where_sql}"  # nosec B608 - generated clauses only
            ]
            facet_params: list[Any] = [*where_params]
            facet_columns = {
                "type": "entity_type",
                "environment": "inventory_environment",
                "provider": "inventory_provider",
                "severity": "finding_severity",
            }
            for facet, column in facet_columns.items():
                facet_where, current_params = filtered_where(exclude=facet)
                facet_sql.append(
                    f"SELECT '{facet}', {column}, COUNT(*) FROM assets WHERE {facet_where} GROUP BY {column}"  # nosec B608 - static mapping
                )
                facet_params.extend(current_params)
            source_where, source_params = filtered_where(exclude="source")
            facet_sql.append(
                f"""
                    SELECT 'source', value, COUNT(DISTINCT id) FROM (
                        SELECT assets.id, NULLIF(LOWER(src.value), '') AS value
                        FROM assets JOIN json_each(assets.data_sources) src
                        WHERE {source_where}
                        UNION ALL
                        SELECT assets.id, NULL FROM assets
                        WHERE {source_where} AND json_array_length(data_sources) = 0
                    ) source_buckets GROUP BY value
                """  # nosec B608 - source_where contains only generated placeholders
            )
            facet_params.extend([*source_params, *source_params])
            facet_rows = conn.execute(inventory_cte(facets=True) + " UNION ALL ".join(facet_sql), [*cte_params, *facet_params]).fetchall()
            facets: dict[str, list[dict[str, Any]]] = {name: [] for name in ("type", "source", "provider", "environment", "severity")}
            total = 0
            for facet, value, count in facet_rows:
                if facet == "__total__":
                    total = int(count or 0)
                    continue
                facets[str(facet)].append({"value": value if value not in {"", None} else None, "count": int(count)})
            for buckets in facets.values():
                buckets.sort(key=lambda bucket: (-int(bucket["count"]), "" if bucket["value"] is None else str(bucket["value"])))

            row_params = [*cte_params, *where_params]
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                    AND (severity_id < ?
                      OR (severity_id = ? AND risk_score < ?)
                      OR (severity_id = ? AND risk_score = ? AND label > ?)
                      OR (severity_id = ? AND risk_score = ? AND label = ? AND id > ?))
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                inventory_cte()
                + f"""
                    SELECT id, entity_type, label, category_uid, class_uid, type_uid,
                           status, risk_score, severity, severity_id, first_seen, last_seen,
                           attributes, compliance_tags, data_sources, dimensions
                    FROM assets
                    WHERE {where_sql} {cursor_clause}
                    ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                    LIMIT ? OFFSET ?
                """,  # nosec B608 - clauses contain only generated placeholders
                [*row_params, limit + 1, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit or (not cursor and offset + limit < total)
            nodes = [self._node_from_row(row) for row in rows[:limit]]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None

            finding_summaries, relationship_counts = self._inventory_page_context(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                node_ids={node.id for node in nodes},
                finding_types=finding_types,
            )
            finding_count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE tenant_id = ? AND scan_id = ? AND entity_type IN ({finding_placeholders})",  # nosec B608 - placeholders only
                    [tenant_id, effective_scan_id, *finding_types],
                ).fetchone()[0]
                or 0
            )
            return {
                "scan_id": effective_scan_id,
                "created_at": created_at,
                "nodes": nodes,
                "total": total,
                "next_cursor": next_cursor,
                "facets": facets,
                "finding_summaries": finding_summaries,
                "relationship_counts": relationship_counts,
                "finding_count": finding_count,
            }
        finally:
            conn.close()

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return [], 0, None
        try:
            conn_ro: sqlite3.Connection = conn
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return [], 0, None
            fts_query = self._search_query_expression(query)
            search_where = [
                "gns.tenant_id = ?",
                "gns.scan_id = ?",
            ]
            params: list[Any] = [tenant_id, effective_scan_id]
            like_query = f"%{_escape_like_query(query.lower())}%"

            def _run_search(*, use_fts: bool) -> tuple[list[UnifiedNode], int, str | None]:
                local_where = list(search_where)
                local_params = list(params)
                if use_fts:
                    local_where.append("gns.graph_node_search MATCH ?")
                    local_params.append(scoped_search_expression(fts_query, tenant_id=tenant_id, scan_id=effective_scan_id))
                else:
                    local_where.append("gns.search_text LIKE ? ESCAPE '\\'")
                    local_params.append(like_query)
                if entity_types:
                    placeholders = ",".join("?" for _ in entity_types)
                    local_where.append(f"gn.entity_type IN ({placeholders})")
                    local_params.extend(sorted(entity_types))
                sev_sql, sev_params = severity_floor_sql(min_severity_rank, column="gn.severity_id", entity_column="gn.entity_type")
                if sev_sql:
                    local_where.append(sev_sql)
                    local_params.extend(sev_params)
                if compliance_prefixes:
                    prefix_filters = []
                    for prefix in sorted(compliance_prefixes):
                        clause, clause_params = self._compliance_prefix_filter("gns.compliance_tags", prefix)
                        prefix_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(prefix_filters) + ")")
                if data_sources:
                    source_filters = []
                    for source in sorted(data_sources):
                        clause, clause_params = self._space_token_filter("gns.data_sources", source)
                        source_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(source_filters) + ")")
                row_params = [*search_rank.match_rank_params(query), *local_params]
                cursor_clause = ""
                if cursor:
                    cursor_clause = search_rank.search_cursor_clause(rank="match_rank", columns=search_rank.SEARCH_COLUMNS, placeholder="?")
                    row_params.extend(search_rank.search_cursor_params(cursor))

                where_sql = " AND ".join(local_where)
                # Materialize only ranking keys once. Counting and sorting the
                # same FTS matches previously repeated every node join; hydrate
                # full evidence only for the selected page. A LEFT JOIN retains
                # the exact total even when an offset/cursor exhausts the page.
                rows = conn_ro.execute(
                    f"""WITH matches AS MATERIALIZED (
                        SELECT gn.rowid AS node_rowid, gn.id, gn.severity_id, gn.risk_score, gn.label,
                            {search_rank.SQLITE_RANK} AS match_rank
                        {from_clause} WHERE {where_sql}
                    ), page AS (
                        SELECT * FROM matches WHERE 1=1 {cursor_clause}
                        ORDER BY match_rank ASC, severity_id DESC, risk_score DESC, label ASC, id ASC LIMIT ? OFFSET ?
                    ) SELECT gn.*, page.match_rank AS search_match_rank, totals.match_total
                    FROM (SELECT COUNT(*) AS match_total FROM matches) totals
                    LEFT JOIN page ON 1=1 LEFT JOIN graph_nodes gn ON gn.rowid = page.node_rowid
                    ORDER BY page.match_rank ASC, page.severity_id DESC, page.risk_score DESC, page.label ASC, page.id ASC
                    """,  # nosec B608 - fixed internal clauses; all search/filter/cursor values are bound
                    [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
                ).fetchall()
                total = int(rows[0]["match_total"])
                rows = [row for row in rows if row["id"] is not None]
                has_more = len(rows) > limit if cursor else offset + limit < total
                rows = rows[:limit]
                nodes, next_cursor = [self._node_from_row(row) for row in rows], search_rank.sqlite_next_cursor(rows, has_more)
                return nodes, total, next_cursor

            from_clause = """
                FROM graph_node_search gns
                JOIN graph_nodes gn
                  ON gn.id = gns.node_id
                 AND gn.scan_id = gns.scan_id
                 AND gn.tenant_id = gns.tenant_id
            """
            use_fts = bool(fts_query and self._should_use_fts(query))
            try:
                return _run_search(use_fts=use_fts)
            except sqlite3.OperationalError:
                if not use_fts:
                    raise
                return _run_search(use_fts=False)
        finally:
            conn.close()
