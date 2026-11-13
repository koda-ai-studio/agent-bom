"""Lean, sargable read of one snapshot for the grouped full map.

Every statement filters on ``(tenant_id, scan_id)``, the leading columns of
the snapshot indexes on both SQLite and Postgres, and no statement decodes
evidence, provenance or dimensions. Attributes are read only for the two node
types whose group depends on them (a package's ecosystem, a cloud resource's
resource type). Attack-path hops come from the highest-risk paths only, so a
snapshot with a very large path table still answers in bounded time.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.graph.cluster_index import TOP_PATHS_FOR_BUNDLES, EdgeRow, NodeRow, hop_pairs

#: Hops of at most this many of the snapshot's highest-risk paths mark nodes as "on an attack path".
MAX_PATHS_FOR_MEMBERSHIP = 5000


def _attribute(raw: Any, key: str) -> str:
    if not raw:
        return ""
    try:
        value = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return ""
    return str(value.get(key) or "") if isinstance(value, dict) else ""


def _sqlite_rows(conn: Any, params: tuple[str, str]) -> tuple[list[NodeRow], list[EdgeRow]]:
    # One JSON batch per statement: sqlite3 re-acquires the GIL per cursor row,
    # which at 200k rows costs several times the query itself.
    node_batch = conn.execute(
        """SELECT json_group_array(json_array(id, entity_type, label, severity, risk_score,
                  CASE entity_type WHEN 'package' THEN json_extract(attributes, '$.ecosystem')
                                   WHEN 'cloud_resource' THEN json_extract(attributes, '$.resource_type') END))
           FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?""",
        params,
    ).fetchone()
    nodes: list[NodeRow] = [
        (
            str(i),
            str(t or ""),
            str(label or i),
            str(sev or ""),
            float(risk or 0.0),
            str(attr or "") if t == "package" else "",
            str(attr or "") if t == "cloud_resource" else "",
        )
        for i, t, label, sev, risk, attr in json.loads(node_batch[0] or "[]")
    ]
    del node_batch
    edge_batch = conn.execute(
        "SELECT json_group_array(json_array(source_id, target_id, relationship)) FROM graph_edges WHERE tenant_id = ? AND scan_id = ?",
        params,
    ).fetchone()
    edges: list[EdgeRow] = [(str(s), str(t), str(r)) for s, t, r in json.loads(edge_batch[0] or "[]")]
    return nodes, edges


def _postgres_rows(conn: Any, params: tuple[str, str]) -> tuple[list[NodeRow], list[EdgeRow]]:
    node_rows = conn.execute(
        """SELECT id, entity_type, label, severity, risk_score,
                  CASE WHEN entity_type IN ('package', 'cloud_resource') THEN attributes ELSE NULL END
           FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s""",
        params,
    ).fetchall()
    nodes: list[NodeRow] = [
        (
            str(i),
            str(t or ""),
            str(label or i),
            str(sev or ""),
            float(risk or 0.0),
            _attribute(attrs, "ecosystem") if t == "package" else "",
            _attribute(attrs, "resource_type") if t == "cloud_resource" else "",
        )
        for i, t, label, sev, risk, attrs in node_rows
    ]
    del node_rows
    edges: list[EdgeRow] = [
        (str(s), str(t), str(r))
        for s, t, r in conn.execute(
            "SELECT source_id, target_id, relationship FROM graph_edges WHERE tenant_id = %s AND scan_id = %s", params
        ).fetchall()
    ]
    return nodes, edges


def load_cluster_rows(
    conn: Any, *, tenant_id: str, scan_id: str, postgres: bool = False
) -> tuple[list[NodeRow], list[EdgeRow], set[str], set[tuple[str, str]]]:
    """Nodes, edges and attack-path hops of one resolved snapshot, scoped to one tenant."""
    m = "%s" if postgres else "?"
    params = (tenant_id, scan_id)
    nodes, edges = _postgres_rows(conn, params) if postgres else _sqlite_rows(conn, params)
    hops: set[str] = set()
    paths: list[list[str]] = []
    for (path_nodes,) in conn.execute(
        f"""SELECT path_nodes FROM attack_paths WHERE tenant_id = {m} AND scan_id = {m}
            ORDER BY composite_risk DESC LIMIT {m}""",  # nosec B608
        (*params, MAX_PATHS_FOR_MEMBERSHIP),
    ).fetchall():
        try:
            decoded = json.loads(path_nodes) if isinstance(path_nodes, (str, bytes)) else path_nodes
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, list):
            path = [str(hop) for hop in decoded if isinstance(hop, str)]
            hops.update(path)
            paths.append(path)
    return nodes, edges, hops, hop_pairs(paths[:TOP_PATHS_FOR_BUNDLES])


__all__ = ["MAX_PATHS_FOR_MEMBERSHIP", "load_cluster_rows"]
