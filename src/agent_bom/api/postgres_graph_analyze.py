"""Refresh graph planner statistics after a large snapshot save.

The app role is DML-only and cannot ``ANALYZE``. Migration ``20261114_01``
grants it one narrow function, ``public.abom_analyze_graph_tables()``: a
``SECURITY DEFINER`` call with no arguments that analyzes ``graph_nodes`` and
``graph_edges`` only, once per 60 seconds at most. Without it the reads right
after a large push plan without statistics until autovacuum reaches the new
rows. A failure (for example a database not yet migrated) is logged and never
fails the save that already committed.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

ANALYZE_AFTER_ROWS = 20_000


def refresh_graph_statistics(conn: Any, *, rows: int) -> None:
    """Analyze the graph tables through the narrow function when a save wrote ``rows`` or more rows."""
    if rows < ANALYZE_AFTER_ROWS:
        return
    import psycopg

    try:
        conn.execute("SELECT public.abom_analyze_graph_tables()")
        conn.commit()
    except psycopg.Error as exc:
        try:
            conn.rollback()
        except psycopg.Error:
            pass  # the connection is already unusable; the pool discards it and the warning below reports the cause
        # Only the type: a driver message can carry connection details.
        logger.warning(
            "Graph planner statistics were not refreshed after a %s-row save (%s); autovacuum will refresh them", rows, type(exc).__name__
        )


__all__ = ["ANALYZE_AFTER_ROWS", "refresh_graph_statistics"]
