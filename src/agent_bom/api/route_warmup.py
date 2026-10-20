"""Compile the route table at boot instead of on the first request.

FastAPI builds each included router's effective routes lazily, the first time
a request walks it. With ~200 routes that cost ~1.9 s of CPU and landed on
whichever request arrived first (measured on ``GET /v1/graph``). Matching a
path no route serves walks every router once, through the public Starlette
``BaseRoute.matches`` interface, so the table is built before traffic.

Best-effort: one daemon thread, never raises, opt out with
``AGENT_BOM_ROUTE_WARMUP=0``. A request that arrives mid-warm-up waits on
FastAPI's own build lock rather than building twice.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from agent_bom.core.settings import SettingError, env_bool

logger = logging.getLogger(__name__)

_UNSERVED_PATH = "/__agent_bom_route_warmup__"


def _scope(method: str) -> dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": _UNSERVED_PATH,
        "raw_path": _UNSERVED_PATH.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "scheme": "http",
        "server": ("127.0.0.1", 0),
    }


def warm_route_tables(app: Any) -> bool:
    """Walk every route once so lazily-built routers compile now; True on success."""
    try:
        for route in list(app.router.routes):
            route.matches(_scope("GET"))
    except Exception:  # broad-except: boot warm-up boundary; on any failure the first request builds the table lazily as before.
        logger.debug("route table warm-up skipped", exc_info=False)
        return False
    return True


def _enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_ROUTE_WARMUP", True)
    except SettingError:
        return True


def start_route_warmup(app: Any) -> threading.Thread | None:
    """Warm the route table on a daemon thread; return it, or None when disabled."""
    if not _enabled():
        return None
    thread = threading.Thread(target=warm_route_tables, args=(app,), name="route-table-warmup", daemon=True)
    try:
        thread.start()
    except RuntimeError:
        return None
    return thread


__all__ = ["start_route_warmup", "warm_route_tables"]
