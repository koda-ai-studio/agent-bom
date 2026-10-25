"""Run demo-estate seeding off the API startup path.

Liveness answers as soon as the process is up; readiness reports the seed in
flight until the showcase evidence has landed. The maintenance loop can reseed
concurrently with the startup seed, so every seed run is serialized.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import socket
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, TypeVar

from agent_bom.demo_estate import demo_estate_enabled
from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT
from agent_bom.storage.state_home import state_dir

_logger = logging.getLogger(__name__)

_F = TypeVar("_F", bound=Callable[..., Any])
_seed_run_lock = threading.Lock()
_boot_seed_done = threading.Event()
_boot_seed_done.set()

DEMO_SEEDING_SUMMARY = "Seeding the demo estate. Posture appears when the curated scan lands."
SEEDING_CODE = "current_estate_seeding"
SEEDING_MESSAGE = "The demo estate is still being seeded; retry the read shortly."
SEEDING_RETRY_AFTER_SECONDS = 2


def serialized_seed(fn: _F) -> _F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with _seed_run_lock:
            return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


# Other processes reading the same demo state (an out-of-process MCP server)
# see the seed through this marker in the shared state directory, which also
# holds the demo graph. A seeder that crashed leaves a marker naming a dead
# process on this host; one from another host expires after the TTL.
SEED_MARKER_NAME = "demo-seed-in-progress.json"
SEED_MARKER_TTL_SECONDS = 1800.0
SEED_TENANTS = (SHOWCASE_TENANT,)


def _marker_path() -> Path:
    return state_dir() / SEED_MARKER_NAME


def mark_seed_started(tenants: tuple[str, ...] = SEED_TENANTS) -> None:
    """Record, for every process sharing this state, that the seed is landing for *tenants*."""
    path = _marker_path()
    payload = {"tenants": list(tenants), "started_at": time.time(), "pid": os.getpid(), "host": socket.gethostname()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        staging = path.with_name(f".{path.name}.{os.getpid()}")
        staging.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(staging, path)
    except OSError:
        _logger.warning("demo seed marker could not be written; other processes will not see the seed", exc_info=False)


def clear_seed_marker() -> None:
    try:
        _marker_path().unlink(missing_ok=True)
    except OSError:
        _logger.warning("demo seed marker could not be removed", exc_info=False)


def _marker_payload() -> dict[str, Any] | None:
    try:
        payload = json.loads(_marker_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _persisted_seed_active(tenant_id: str | None) -> bool:
    payload = _marker_payload()
    if payload is None:
        return False
    try:
        started_at, pid = float(payload["started_at"]), int(payload["pid"])
    except (KeyError, TypeError, ValueError):
        return False
    if time.time() - started_at > SEED_MARKER_TTL_SECONDS:
        return False
    if payload.get("host") == socket.gethostname() and not _process_alive(pid):
        return False
    return tenant_id is None or tenant_id in (payload.get("tenants") or [])


def demo_estate_seeding(tenant_id: str | None = None) -> bool:
    """Whether a demo seed is landing here, or in another process sharing this state (for *tenant_id*)."""
    return not _boot_seed_done.is_set() or _persisted_seed_active(tenant_id)


def demo_seed_state() -> Literal["pending", "complete"] | None:
    """``/health`` view of the boot seed: ``None`` outside demo mode."""
    if not demo_estate_enabled():
        return None
    return "pending" if demo_estate_seeding() else "complete"


def wait_for_demo_estate_boot_seed(timeout: float | None = None) -> bool:
    return _boot_seed_done.wait(timeout)


_POSTURE_PRECOMPUTE_READY_TIMEOUT_SECONDS = 120.0


def _run_boot_seed() -> None:
    from agent_bom.api.posture_counts_cache import wait_for_posture_precompute
    from agent_bom.demo_estate import bootstrap

    mark_seed_started()
    try:
        bootstrap.maybe_bootstrap_demo_estate()
        # The seed's scan writes schedule the posture-count precompute; stay
        # not-ready until it lands so the first read does not repeat it.
        if not wait_for_posture_precompute(_POSTURE_PRECOMPUTE_READY_TIMEOUT_SECONDS):
            _logger.warning("demo estate posture precompute still running at readiness")
    finally:
        _boot_seed_done.set()
        clear_seed_marker()


async def _seed_then(after: Callable[[], Awaitable[None]] | None) -> None:
    try:
        await asyncio.to_thread(_run_boot_seed)
    except Exception:  # noqa: BLE001
        _logger.warning("demo estate bootstrap skipped", exc_info=False)
    if after is not None:
        from agent_bom.api import foreground_activity

        await asyncio.to_thread(foreground_activity.defer_until_idle)
        await after()


def start_demo_estate_boot_seed(after: Callable[[], Awaitable[None]] | None = None) -> asyncio.Task[None]:
    """Schedule the startup seed; readiness reports seeding from this call on."""
    _boot_seed_done.clear()
    mark_seed_started()
    return asyncio.create_task(_seed_then(after))


async def drain_demo_estate_boot_seed(task: asyncio.Task[None] | None, timeout: float) -> None:
    """Let an in-flight seed finish writing before stores close; its thread cannot be cancelled."""
    if task is not None and not task.done():
        await asyncio.wait({task}, timeout=timeout)


__all__ = [
    "DEMO_SEEDING_SUMMARY",
    "SEED_MARKER_TTL_SECONDS",
    "clear_seed_marker",
    "mark_seed_started",
    "demo_estate_seeding",
    "demo_seed_state",
    "drain_demo_estate_boot_seed",
    "serialized_seed",
    "start_demo_estate_boot_seed",
    "wait_for_demo_estate_boot_seed",
]
