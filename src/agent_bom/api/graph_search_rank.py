"""Name-first ranking for graph search, the same for every entity type.

The entity the query names ranks first: its id equals the query, or the id
past its type prefix does (``agent:langchain-service`` for
``langchain-service``). Then a node whose label equals the query (a grant or
finding named after that entity), then a label that starts with it, then every
other match (attribute and evidence text). Severity and risk order only within
a rank. Search keyset cursors carry that rank so pages stay gap-free.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from agent_bom.api.graph_store_support import _escape_like_query, decode_graph_cursor

OTHER_MATCH = 3


def match_rank_sql(*, label: str, node_id: str, placeholder: str, position: str) -> str:
    """``position`` is the dialect's substring-position function (``instr`` / ``strpos``)."""
    p = placeholder
    suffix = f"substr({node_id}, {position}({node_id}, ':') + 1)"
    return (
        f"CASE WHEN lower({node_id}) = lower({p}) OR ({position}({node_id}, ':') > 0 AND lower({suffix}) = lower({p})) THEN 0 "
        f"WHEN lower({label}) = lower({p}) THEN 1 "
        f"WHEN lower({label}) LIKE lower({p}) ESCAPE '\\' THEN 2 ELSE {OTHER_MATCH} END"
    )


def match_rank_params(query: str) -> list[Any]:
    return [query, query, query, f"{_escape_like_query(query)}%"]


def encode_search_cursor(rank: int, severity_id: int, risk_score: float, label: str, node_id: str) -> str:
    payload = json.dumps([int(rank), int(severity_id), float(risk_score), label, node_id], separators=(",", ":"), ensure_ascii=True)
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_search_cursor(cursor: str) -> tuple[int, int, float, str, str]:
    """A five-part search cursor; a legacy four-part graph cursor resumes among non-name matches."""
    try:
        values = json.loads(base64.urlsafe_b64decode((cursor + "=" * (-len(cursor) % 4)).encode()).decode())
    except Exception as exc:  # noqa: BLE001 - normalized into ValueError for route handling
        raise ValueError("Invalid graph cursor") from exc
    if isinstance(values, list) and len(values) == 5:
        rank, severity_id, risk_score, label, node_id = values
        return int(rank), int(severity_id), float(risk_score), str(label), str(node_id)
    return (OTHER_MATCH, *decode_graph_cursor(cursor))


def search_cursor_clause(*, rank: str, columns: tuple[str, str, str, str], placeholder: str) -> str:
    """Rows after the cursor in ``rank ASC, severity DESC, risk DESC, label ASC, id ASC`` order."""
    sev, risk, label, node_id = columns
    p = placeholder
    return f"""
        AND (
            {rank} > {p}
            OR ({rank} = {p} AND (
                {sev} < {p}
                OR ({sev} = {p} AND {risk} < {p})
                OR ({sev} = {p} AND {risk} = {p} AND {label} > {p})
                OR ({sev} = {p} AND {risk} = {p} AND {label} = {p} AND {node_id} > {p})
            ))
        )
    """


def search_cursor_params(cursor: str) -> list[Any]:
    rank, sev, risk, label, node_id = decode_search_cursor(cursor)
    return [rank, rank, sev, sev, risk, sev, risk, label, sev, risk, label, node_id]


SEARCH_COLUMNS = ("severity_id", "risk_score", "label", "id")
SQLITE_RANK = match_rank_sql(label="gn.label", node_id="gn.id", placeholder="?", position="instr")
PG_RANK = match_rank_sql(label="gn.label", node_id="gn.id", placeholder="%s", position="strpos")


def sqlite_next_cursor(rows: list[Any], has_more: bool) -> str | None:
    last = rows[-1] if has_more and rows else None
    if last is None:
        return None
    return encode_search_cursor(last["search_match_rank"], last["severity_id"], last["risk_score"], last["label"], last["id"])


def pg_ranked_search_rows(
    conn: Any, from_clause: str, where_sql: str, params: list[Any], query: str, cursor: str | None, limit: int, offset: int, total: int
) -> tuple[list[Any], bool, str | None]:
    """Name matches first, then severity and risk; the trailing column is the match rank."""
    cursor_clause = search_cursor_clause(rank="match_rank", columns=SEARCH_COLUMNS, placeholder="%s") if cursor else ""
    rows = conn.execute(
        f"""
        SELECT * FROM (
            SELECT
                gn.id, gn.entity_type, gn.label, gn.category_uid, gn.class_uid, gn.type_uid,
                gn.status, gn.risk_score, gn.severity, gn.severity_id, gn.first_seen, gn.last_seen,
                gn.attributes, gn.compliance_tags, gn.data_sources, gn.dimensions, {PG_RANK} AS match_rank
            {from_clause} WHERE {where_sql}
        ) ranked WHERE 1=1 {cursor_clause}
        ORDER BY match_rank ASC, severity_id DESC, risk_score DESC, label ASC, id ASC LIMIT %s OFFSET %s
        """,  # nosec B608 - fixed internal clauses; all search/filter/cursor values are bound
        [
            *match_rank_params(query),
            *params,
            *(search_cursor_params(cursor) if cursor else []),
            limit + 1 if cursor else limit,
            0 if cursor else offset,
        ],
    ).fetchall()
    has_more = len(rows) > limit if cursor else offset + limit < total
    rows = rows[:limit]
    last = rows[-1] if has_more and rows else None
    return rows, has_more, encode_search_cursor(last[16], last[9], last[7], last[2], last[0]) if last is not None else None
