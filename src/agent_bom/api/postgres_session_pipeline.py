"""Send a connection's tenant session prelude as one pipeline.

Every RLS transaction starts with BEGIN, an optional isolation level and the
tenant ``set_config`` calls. Sent one by one, each waits on the server, and
each wait gives up the GIL: while an ingest keeps another thread busy, taking
it back costs up to the interpreter's switch interval, so a read's latency
under ingest grows with its waits. In one pipeline the prelude waits twice
(psycopg syncs its BEGIN on its own) instead of once per statement.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from typing import Any


@contextmanager
def session_pipeline(conn: Any) -> Iterator[None]:
    """Pipeline ``conn``'s statements when it is a real psycopg connection; otherwise send them as they come."""
    try:
        from psycopg import Connection
    except ImportError:  # psycopg is an optional extra; stand-in connections send statements directly.
        Connection = None  # type: ignore[assignment,misc]  # noqa: N806
    with conn.pipeline() if Connection is not None and isinstance(conn, Connection) else nullcontext():
        yield
