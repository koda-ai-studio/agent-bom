"""Uvicorn server settings shared by ``agent-bom serve`` and ``agent-bom api``."""

from __future__ import annotations

from typing import Any

from agent_bom.core.graceful_shutdown import graceful_shutdown_seconds


# "auto" lifespan logs a failed startup as "unsupported" and serves 500s; "on"
# exits. Idle keep-alive and an in-flight cap bound a slow-connection flood; a
# bounded in-flight wait after SIGTERM leaves the lifespan drain its budget.
# The API middleware logs every request once, so Uvicorn's access line is off.
def uvicorn_server_kwargs() -> dict[str, Any]:
    return {
        "access_log": False,
        "lifespan": "on",
        "timeout_keep_alive": 5,
        "limit_concurrency": 500,
        "proxy_headers": False,
        "timeout_graceful_shutdown": graceful_shutdown_seconds(),
    }
