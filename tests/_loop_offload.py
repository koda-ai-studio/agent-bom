"""Prove blocking work runs off the event loop without timing the loop.

The blocking stand-in holds until the test releases it. If the code under test
ran it on the loop, the test's own coroutine could not resume until the stand-in
gave up, so it would find the call already finished. Off the loop, the test
resumes while the call is still held open.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

_HOLD_SECONDS = 30


class BlockingCall:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def block(self) -> None:
        self.entered.set()
        self.release.wait(_HOLD_SECONDS)
        self.finished.set()


async def _until_entered(call: BlockingCall) -> None:
    while not call.entered.is_set():
        await asyncio.sleep(0.005)


async def assert_runs_off_loop(task: asyncio.Future[Any], call: BlockingCall, what: str) -> Any:
    """Await *task* after proving its blocking *call* never held the event loop."""
    try:
        await asyncio.wait_for(_until_entered(call), _HOLD_SECONDS + 5)
        assert not call.finished.is_set(), f"event loop was blocked during {what}: offload ineffective"
        assert not task.done(), f"{what} should still be in flight"
    finally:
        call.release.set()
    return await task
