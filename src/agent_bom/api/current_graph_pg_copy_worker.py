"""The child process that runs one PostgreSQL current-graph row copy.

Started by ``current_graph_pg_copy_child.copy_in_child`` with its request on
stdin and its database connection from the inherited environment, and runs
below the API's CPU priority. It exits
``EXIT_COPIED`` after committing the copy, ``EXIT_DECLINED`` when the copy would
not equal a rewrite, and ``EXIT_FAILED`` on any error, reporting only the
error's type: a message could carry connection details. It ends itself if the
API that started it is gone.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from types import TracebackType

from agent_bom.api.current_graph_pg_copy import copy_postgres_rows
from agent_bom.api.current_graph_pg_copy_child import EXIT_COPIED, EXIT_DECLINED, EXIT_FAILED, REQUEST_FIELDS
from agent_bom.api.postgres_common import _get_pool, set_current_tenant

PARENT_POLL_SECONDS = 1.0
# Below the API, so the copy and the database serving it do not take its cores.
NICE_INCREMENT = 10


def lower_priority() -> None:
    """Run the copy at lower CPU priority than the API; a platform or policy that refuses it changes nothing."""
    nice = getattr(os, "nice", None)
    if nice is None:
        return
    try:
        nice(NICE_INCREMENT)
    except OSError:
        return


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


def report_type_only(kind: type[BaseException], _error: BaseException, _trace: TracebackType | None) -> None:
    sys.stderr.write(f"{kind.__name__}\n")
    sys.stderr.flush()
    os._exit(EXIT_FAILED)


def main() -> int:
    sys.excepthook = report_type_only
    lower_priority()
    request = json.loads(sys.stdin.buffer.read())
    _watch_parent(int(request["parent_pid"]))
    set_current_tenant(str(request["tenant"]))
    copied = copy_postgres_rows(_get_pool(), str(request["cache_path"]), **{name: str(request[name]) for name in REQUEST_FIELDS})
    return EXIT_COPIED if copied else EXIT_DECLINED


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["NICE_INCREMENT", "exit_if_orphaned", "lower_priority", "main", "report_type_only"]
