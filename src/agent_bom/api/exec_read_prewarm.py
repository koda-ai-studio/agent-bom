"""Warm the exec reads a dashboard opens first, right after a seed or a push.

Posture counts, the compliance summary, the fix-first view and the executive
brief rebuild from every stored scan on their first read after the evidence
generation moves: 1.3-3.7 s each on the demo estate (measured 2026-11-01).
Every push and every demo seed moves the generation, so the next visitor paid
all four. This module runs those four reads once, in one background thread,
through the same route functions the dashboard calls, so the response cache
already holds the new generation when the first request arrives.

Bounded and best-effort: at most one warm-up queued per tenant (repeat pushes
coalesce), one worker thread per process, never on the request path, and a
failing read is logged and skipped. ``AGENT_BOM_EXEC_PREWARM=0`` disables it.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

from starlette.requests import Request

from agent_bom.api.routes.brief import get_executive_brief
from agent_bom.api.routes.compliance import get_compliance_summary, get_posture_counts
from agent_bom.api.routes.graph_routes.views import get_fix_first_graph_view
from agent_bom.core.settings import SettingError, env_bool
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

#: ``(route function, request path, query params)`` in the order a dashboard open requests them.
EXEC_READS: tuple[tuple[Callable[..., Awaitable[Any]], str, dict[str, Any]], ...] = (
    (get_posture_counts, "/v1/posture/counts", {}),
    (get_compliance_summary, "/v1/compliance/summary", {}),
    (get_fix_first_graph_view, "/v1/graph/views/fix-first", {"scan_id": None, "cve": "", "package": "", "agent": "", "limit": 8}),
    (get_executive_brief, "/v1/brief", {"limit": 5}),
)

_LOCK = threading.Lock()
_PENDING: set[str] = set()
_WORKER: threading.Thread | None = None


def exec_prewarm_enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_EXEC_PREWARM", True)
    except SettingError:
        return True


def _warm_request(tenant_id: str, path: str, params: dict[str, Any]) -> Request:
    """A tenant-bound GET the route functions accept; ``auth_method`` marks it as an internal read."""
    query = urlencode({key: value for key, value in params.items() if value is not None})
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": query.encode(),
            "headers": [],
            "client": ("prewarm", 0),
            "server": ("prewarm", 0),
            "state": {"tenant_id": tenant_id, "auth_method": "prewarm"},
        }
    )


async def warm_exec_reads(tenant_id: str) -> dict[str, bool]:
    """Run every exec read once for ``tenant_id``; returns which ones completed."""
    outcome: dict[str, bool] = {}
    for endpoint, path, params in EXEC_READS:
        try:
            await endpoint(_warm_request(tenant_id, path, params), **params)
            outcome[endpoint.__name__] = True
        except Exception as exc:  # broad-except: a warm-up read that fails is skipped; the real request computes it instead
            logger.debug("exec prewarm skipped %s: %s", endpoint.__name__, sanitize_text(exc))
            outcome[endpoint.__name__] = False
    return outcome


def _drain() -> None:
    global _WORKER
    while True:
        with _LOCK:
            if not _PENDING:
                _WORKER = None
                return
            tenant_id = _PENDING.pop()
        try:
            asyncio.run(warm_exec_reads(tenant_id))
        except Exception as exc:  # broad-except: the worker must survive one tenant's failure to serve the next queued tenant
            logger.debug("exec prewarm failed for a tenant: %s", sanitize_text(exc))


def schedule_exec_prewarm(tenant_id: str) -> bool:
    """Queue a warm-up for ``tenant_id``; returns whether one is now pending or running."""
    if not exec_prewarm_enabled() or not tenant_id:
        return False
    global _WORKER
    with _LOCK:
        _PENDING.add(tenant_id)
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_drain, name="agent-bom-exec-prewarm", daemon=True)
            _WORKER.start()
    return True


def pending_exec_prewarms() -> set[str]:
    with _LOCK:
        return set(_PENDING)


__all__ = ["EXEC_READS", "exec_prewarm_enabled", "pending_exec_prewarms", "schedule_exec_prewarm", "warm_exec_reads"]
