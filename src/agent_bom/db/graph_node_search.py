"""SQLite graph search indexing; scope is an optimization, never authorization.

Shared by every SQLite graph writer: the API store and the CLI ``save_graph``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator

from agent_bom.graph import EntityType, NodeDimensions, NodeStatus, UnifiedNode

_CREATE_SEARCH = """CREATE VIRTUAL TABLE IF NOT EXISTS graph_node_search USING fts5(
    tenant_id, scan_id, node_id UNINDEXED, entity_type, severity,
    compliance_tags, data_sources, search_text
)"""
_SEARCH_COLUMNS = "rowid, tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text"


def ensure_search_index(conn: sqlite3.Connection) -> None:
    """Upgrade the derived index within the caller's reserved write transaction.

    Columns and their contents stay compatible with older writers. Rebuild the
    FTS postings atomically; an interrupted copy/drop/rename must roll back with
    the transaction. This may require substantial startup time and spare disk.
    """
    if not conn.in_transaction:
        raise RuntimeError("Search index initialization requires a write transaction")
    row = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'graph_node_search'").fetchone()
    if row is None:
        conn.execute(_CREATE_SEARCH)
    elif re.search(r"\b(?:tenant_id|scan_id)\s+UNINDEXED\b", row[0], re.IGNORECASE):
        rebuild_search_index(conn, scoped=True)


def rebuild_search_index(conn: sqlite3.Connection, *, scoped: bool) -> None:
    """Rebuild postings without changing rows; caller commits or rolls back.

    Use ``scoped=False`` offline before starting older readers on rollback.
    Mixed reader versions otherwise search different sets of FTS columns.
    """
    if not conn.in_transaction:
        raise RuntimeError("Search index rebuild requires a write transaction")
    statement = _CREATE_SEARCH.replace("IF NOT EXISTS ", "").replace("graph_node_search", "graph_node_search_upgrade")
    if not scoped:
        statement = statement.replace("tenant_id, scan_id,", "tenant_id UNINDEXED, scan_id UNINDEXED,")
    conn.execute(statement)
    conn.execute(f"INSERT INTO graph_node_search_upgrade ({_SEARCH_COLUMNS}) SELECT {_SEARCH_COLUMNS} FROM graph_node_search")  # nosec B608 - fixed internal column names only
    conn.execute("DROP TABLE graph_node_search")
    conn.execute("ALTER TABLE graph_node_search_upgrade RENAME TO graph_node_search")


def scoped_search_expression(query: str, *, tenant_id: str, scan_id: str) -> str:
    """Restrict postings before fetching matches; exact SQL predicates remain.

    Keep user text restricted to the previously searchable columns. FTS scope
    tokens are case/diacritic/punctuation normalized and cannot replace exact
    tenant/snapshot equality. Skip the optimization without a known token:
    opaque punctuation-only, non-ASCII and NUL-containing identifiers remain
    supported by SQL without changing prefix/AND matching into LIKE fallback.
    """
    clauses = [f"{{entity_type severity compliance_tags data_sources search_text}}: ({query})"]
    for column, value in (("tenant_id", tenant_id), ("scan_id", scan_id)):
        if "\x00" not in value and re.search(r"[A-Za-z0-9]", value):
            literal = value.replace('"', '""')
            clauses.append(f'{column}: "{literal}"')
    return " AND ".join(clauses)


def sqlite_node_from_row(row: sqlite3.Row) -> UnifiedNode:
    return UnifiedNode.from_stored(
        id=row["id"],
        entity_type=EntityType(row["entity_type"]),
        label=row["label"],
        category_uid=row["category_uid"],
        class_uid=row["class_uid"],
        type_uid=row["type_uid"],
        status=NodeStatus(row["status"]),
        risk_score=row["risk_score"],
        severity=row["severity"] or "",
        severity_id=row["severity_id"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        attributes=json.loads(row["attributes"]),
        compliance_tags=json.loads(row["compliance_tags"]),
        data_sources=json.loads(row["data_sources"]),
        dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
    )


def node_search_text(node: UnifiedNode) -> str:
    attributes = {key: value for key, value in node.attributes.items() if key != "_agent_bom_canonical_id"}
    assessment = attributes.get("risk_assessment")
    if isinstance(assessment, dict) and assessment.get("status") == "assessed" and "scored_value" not in assessment:
        attributes["risk_assessment"] = {**assessment, "scored_value": node.risk_score}
    parts: list[str] = [
        node.id,
        node.label,
        node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
        node.severity or "",
        " ".join(node.compliance_tags),
        " ".join(node.data_sources),
        json.dumps(attributes, default=str, sort_keys=True),
        json.dumps(node.dimensions.to_dict(), sort_keys=True),
    ]
    return " ".join(part for part in parts if part).lower()


_SNAPSHOT_NODE_SELECT = """
    SELECT
        id, entity_type, label, category_uid, class_uid, type_uid,
        status, risk_score, severity, severity_id, first_seen, last_seen,
        attributes, compliance_tags, data_sources, dimensions
    FROM graph_nodes
    WHERE tenant_id = ? AND scan_id = ?
"""
_SEARCH_INSERT = """
    INSERT INTO graph_node_search (
        tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def write_node_search_batch(conn: sqlite3.Connection, nodes: Iterable[UnifiedNode], *, tenant_id: str, scan_id: str) -> None:
    """Index the writer's bounded node batch without a second database read."""

    def rows() -> Iterator[tuple[object, ...]]:
        for node in nodes:
            # Preserve stored-row enum validation while avoiding reconstruction.
            NodeStatus(node.status)
            yield (
                tenant_id,
                scan_id,
                node.id,
                EntityType(node.entity_type).value,
                (node.severity or "").lower(),
                " ".join(node.compliance_tags).lower(),
                " ".join(node.data_sources).lower(),
                node_search_text(node),
            )

    conn.executemany(_SEARCH_INSERT, rows())


def refresh_snapshot_search_index(conn: sqlite3.Connection, *, tenant_id: str, scan_id: str, batch_size: int) -> None:
    """Rebuild one snapshot's search rows from its stored nodes, in the caller's write transaction.

    Offline repair can rebuild from durable rows. Ordinary snapshot writes
    index their existing node batches directly. Repair rows stream in
    ``batch_size`` chunks: a separate read cursor iterates ``graph_nodes``
    while batches go to ``graph_node_search`` (#4075).
    """
    ensure_search_index(conn)
    conn.execute("DELETE FROM graph_node_search WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
    select_cur = conn.cursor()
    select_cur.row_factory = sqlite3.Row
    select_cur.execute(_SNAPSHOT_NODE_SELECT, (tenant_id, scan_id))

    def _search_row(row: sqlite3.Row) -> tuple[object, ...]:
        node = sqlite_node_from_row(row)
        return (
            tenant_id,
            scan_id,
            node.id,
            node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
            node.severity.lower(),
            " ".join(node.compliance_tags).lower(),
            " ".join(node.data_sources).lower(),
            node_search_text(node),
        )

    try:
        while True:
            batch = select_cur.fetchmany(batch_size)
            if not batch:
                break
            conn.executemany(_SEARCH_INSERT, [_search_row(row) for row in batch])
    finally:
        select_cur.close()
