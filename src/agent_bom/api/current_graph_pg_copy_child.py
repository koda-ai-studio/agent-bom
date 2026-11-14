"""Run the PostgreSQL current-graph row copy in a child process (the API side).

In the API process the row copy held the interpreter lock while it streamed a
5,000-agent estate, and every graph read beside it waited. A child holds none
of the API's lock. Only the copy runs there: the guards, promotion and the
fallback rebuild stay in the API.

The child gets its request (tenant, scan, revision, identity, projection path)
on stdin and its database connection from the environment it inherits, the
same variables and password file the API reads, so no credential appears in
argv. It is bounded: a timeout kills it, any exit other than "copied" makes the
caller rebuild in process, and API shutdown or the parent's death ends it. Its
single SQLite transaction means a child that dies mid-write leaves nothing to
promote. Only the exception's type name crosses back, logged sanitized.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import subprocess  # nosec B404 - fixed interpreter and module, no shell
import sys
import threading

from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

CHILD_MODULE = "agent_bom.api.current_graph_pg_copy_worker"
TIMEOUT_SECONDS = 600.0
EXIT_COPIED = 0
EXIT_DECLINED = 10
EXIT_FAILED = 11
REQUEST_FIELDS = ("tenant", "source_scan", "expected_revision", "identity", "created_at", "write_generation", "evidence_manifest_sha256")

_children: set[subprocess.Popen[bytes]] = set()
_children_lock = threading.Lock()


def live_children() -> list[subprocess.Popen[bytes]]:
    with _children_lock:
        return list(_children)


def terminate_children() -> None:
    """Kill every running copy child (API shutdown and interpreter exit)."""
    for process in live_children():
        try:
            process.kill()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Current graph copy child did not exit on shutdown")


atexit.register(terminate_children)


def _reason(stderr: bytes) -> str:
    lines = [line for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
    return sanitize_text(lines[-1], max_len=120) if lines else "no detail"


def copy_in_child(cache_path: str, *, module: str | None = None, timeout: float | None = None, **fields: str) -> bool:
    """Run the row copy in a child; True only when the child copied and committed."""
    request = {name: fields[name] for name in REQUEST_FIELDS}
    payload = json.dumps({**request, "cache_path": cache_path, "parent_pid": os.getpid()}).encode()
    # One connection is all the child needs; the pool sizing variables are the API's own.
    env = {**os.environ, "AGENT_BOM_POSTGRES_POOL_MIN_SIZE": "1", "AGENT_BOM_POSTGRES_POOL_MAX_SIZE": "1"}
    process = subprocess.Popen(  # noqa: S603 # nosec B603 - fixed interpreter and module; credentials stay in env
        [sys.executable, "-m", module or CHILD_MODULE],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )
    with _children_lock:
        _children.add(process)
    limit = TIMEOUT_SECONDS if timeout is None else timeout
    try:
        _out, err = process.communicate(payload, timeout=limit)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        logger.warning("Current graph row copy child timed out after %.0f s; rebuilding instead", limit)
        return False
    finally:
        with _children_lock:
            _children.discard(process)
    if process.returncode == EXIT_COPIED:
        return True
    if process.returncode != EXIT_DECLINED:
        logger.warning("Current graph row copy child failed (exit %s: %s); rebuilding instead", process.returncode, _reason(err or b""))
    return False


__all__ = [
    "CHILD_MODULE",
    "EXIT_COPIED",
    "EXIT_DECLINED",
    "EXIT_FAILED",
    "REQUEST_FIELDS",
    "TIMEOUT_SECONDS",
    "copy_in_child",
    "live_children",
    "terminate_children",
]
