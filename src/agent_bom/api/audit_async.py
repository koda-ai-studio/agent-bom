"""Await durable audit writes without holding the ASGI event loop."""

from functools import partial
from typing import Any

import anyio.to_thread


async def log_action_async(action: str, **kwargs: Any) -> None:
    from agent_bom.api.audit_log import log_action

    # Keep ordering and propagate storage errors to the caller's existing policy.
    # Cancellation does not abandon a worker that is still recording evidence.
    await anyio.to_thread.run_sync(partial(log_action, action, **kwargs))
