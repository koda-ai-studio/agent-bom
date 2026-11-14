"""A larger SQLite page cache held for one whole-snapshot write or load.

graph_edges carries about a dozen indexes, and every snapshot row is a
random-key insert into each; a whole-snapshot load walks an index and fetches
table rows at random the same way. On SQLite's default 2 MiB cache a
5,000-agent estate (170,330 nodes, 229,197 edges) thrashed it: the cold
current-graph build took about 508 s, and about 60 s with 64 MiB. The cache is
held only for the operation and shrunk back afterwards, also on failure, so
idle connections keep the default footprint.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

logger = logging.getLogger(__name__)

SNAPSHOT_BULK_CACHE_KIB = 64 * 1024


@contextmanager
def snapshot_bulk_cache(conn: sqlite3.Connection) -> Iterator[None]:
    previous = int(conn.execute("PRAGMA cache_size").fetchone()[0])
    if previous < 0 and -previous >= SNAPSHOT_BULK_CACHE_KIB:
        yield  # Already at least this large (an outer holder or an operator setting): leave it.
        return
    conn.execute(f"PRAGMA cache_size = -{SNAPSHOT_BULK_CACHE_KIB}")
    try:
        yield
    finally:
        try:
            conn.execute(f"PRAGMA cache_size = {previous}")
        except sqlite3.Error as exc:  # a closed or broken connection keeps nothing to restore
            logger.debug("Graph bulk cache restore skipped (%s)", type(exc).__name__)


__all__ = ["SNAPSHOT_BULK_CACHE_KIB", "snapshot_bulk_cache"]
