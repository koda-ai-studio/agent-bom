"""Bound collection before it occupies shared API worker threads.

Admission is per serving event loop, inside route authorization. Excess work
fails closed before claiming a lease or contacting a provider. An admitted
transaction keeps its slot through completion even if its caller disconnects.
"""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Callable
from typing import TypeVar

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

T = TypeVar("T")
MAX_WAITERS = 8


class _Gate:
    def __init__(self, limit: int) -> None:
        self.semaphore = asyncio.Semaphore(limit)
        self.waiting = 0


_gates: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, weakref.ReferenceType[_Gate]] = weakref.WeakKeyDictionary()


def _gate() -> _Gate:
    from agent_bom import config

    loop = asyncio.get_running_loop()
    reference = _gates.get(loop)
    gate = reference() if reference is not None else None
    if gate is None:
        # Keep at least one shared worker available when the deployment has two
        # or more. Extra collectors do not help CPU-bound page preparation.
        limit = max(1, min(2, int(config.WORKER_THREAD_LIMIT) - 1))
        gate = _Gate(limit)
        _gates[loop] = weakref.ref(gate)
    return gate


async def run_collection(call: Callable[[], T]) -> T:
    gate = _gate()
    if gate.semaphore.locked():
        if gate.waiting >= MAX_WAITERS:
            raise HTTPException(status_code=429, detail="Too many concurrent collections; retry shortly.", headers={"Retry-After": "1"})
        gate.waiting += 1
        try:
            await gate.semaphore.acquire()
        finally:
            gate.waiting -= 1
    else:
        await gate.semaphore.acquire()

    task = asyncio.create_task(run_in_threadpool(call))

    def completed(done: asyncio.Task[T]) -> None:
        gate.semaphore.release()
        if not done.cancelled():
            done.exception()  # Retrieve failures even when the caller disconnected.

    task.add_done_callback(completed)
    return await asyncio.shield(task)
