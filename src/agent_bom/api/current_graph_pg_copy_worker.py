"""The child process that runs one PostgreSQL current-graph row copy.

Started by ``current_graph_pg_copy_child.copy_in_child`` with its request on
stdin and its database connection from the inherited environment. It exits
``EXIT_COPIED`` after committing the copy, ``EXIT_DECLINED`` when the copy would
not equal a rewrite, ``EXIT_UNREACHABLE`` when the database cannot be reached,
and ``EXIT_FAILED`` on any other error, reporting only the error's type: a
message could carry connection details. It ends itself if the
API that started it is gone.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from types import TracebackType

from agent_bom.api.current_graph_pg_copy import copy_postgres_rows
from agent_bom.api.current_graph_pg_copy_child import EXIT_COPIED, EXIT_DECLINED, EXIT_FAILED, EXIT_UNREACHABLE, REQUEST_FIELDS
from agent_bom.api.postgres_common import _get_pool, set_current_tenant

PARENT_POLL_SECONDS = 1.0


def exit_if_orphaned(*, parent_pid: int) -> None:
    """End the child once the API that started it is gone."""
    if os.getppid() != parent_pid:
        os._exit(EXIT_FAILED)


def _watch_parent(parent_pid: int) -> None:
    def watch() -> None:
        while True:
            exit_if_orphaned(parent_pid=parent_pid)
            threading.Event().wait(PARENT_POLL_SECONDS)

    threading.Thread(target=watch, name="copy-parent-watch", daemon=True).start()


_CONNECTION_FAILURES = {("psycopg", "OperationalError"), ("psycopg_pool", "PoolTimeout")}


def _connection_failure_in_chain(error: BaseException) -> bool:
    """Whether a driver connection failure caused ``error``.

    The role inspection that guards every pool raises its privilege error
    ``from None`` on any failure, but keeps the original as ``__context__``.
    """
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        for cls in type(current).__mro__:
            if (cls.__module__.split(".")[0], cls.__name__) in _CONNECTION_FAILURES:
                return True
        current = current.__cause__ or current.__context__
    return False


def report_type_only(kind: type[BaseException], error: BaseException, _trace: TracebackType | None) -> None:
    unreachable = _connection_failure_in_chain(error)
    sys.stderr.write(f"{'DatabaseUnreachable' if unreachable else kind.__name__}\n")
    sys.stderr.flush()
    os._exit(EXIT_UNREACHABLE if unreachable else EXIT_FAILED)


def main() -> int:
    sys.excepthook = report_type_only
    request = json.loads(sys.stdin.buffer.read())
    _watch_parent(int(request["parent_pid"]))
    set_current_tenant(str(request["tenant"]))
    copied = copy_postgres_rows(_get_pool(), str(request["cache_path"]), **{name: str(request[name]) for name in REQUEST_FIELDS})
    return EXIT_COPIED if copied else EXIT_DECLINED


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["exit_if_orphaned", "main", "report_type_only"]
