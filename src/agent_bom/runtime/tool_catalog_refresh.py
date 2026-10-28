"""Bounded, session-private catalog refreshes for MCP change notifications."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from agent_bom.runtime.detectors import Alert, AlertSeverity
from agent_bom.runtime.tool_catalog_pages import ToolCatalogPages


class CatalogRefreshSession(Protocol):
    """Relay state required for read-only catalog refreshes."""

    process: Any
    detectors: Any
    log_file: Any
    server_stdin_lock: asyncio.Lock

    async def handle_alerts(self, alerts: Any, log_f: Any = None) -> None: ...


@dataclass
class ToolCatalogRefresh:
    """One pending refresh per session, isolated from client pagination and IDs."""

    prefix: str = field(default_factory=lambda: f"agent-bom-catalog-{uuid.uuid4().hex}/")
    sequence: int = 0
    request_id: str | None = None
    pages: ToolCatalogPages = field(default_factory=ToolCatalogPages)
    deadline: asyncio.TimerHandle | None = None
    dirty: bool = False

    def close(self) -> None:
        """Cancel the deadline when the owning proxy session shuts down."""
        self._reset()
        self.dirty = False

    def _reset(self) -> None:
        if self.deadline:
            self.deadline.cancel()
        self.deadline = None
        self.request_id = None
        self.pages = ToolCatalogPages()

    async def _incomplete(self, session: CatalogRefreshSession) -> None:
        self._reset()
        self.dirty = False
        await session.handle_alerts(
            [
                Alert(
                    detector="tool_drift",
                    severity=AlertSeverity.MEDIUM,
                    message="Tool definition recheck unavailable; catalog incomplete",
                    details={"catalog_complete": False, "reason_code": "tool_catalog_incomplete"},
                )
            ],
            session.log_file,
        )

    async def _send(self, session: CatalogRefreshSession, cursor: str | None = None) -> None:
        self.sequence += 1
        self.request_id = f"{self.prefix}{self.sequence}"
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/list",
            "params": {"cursor": cursor} if cursor is not None else {},
        }
        self.pages.note_request(request)
        if self.deadline is None:
            loop = asyncio.get_running_loop()
            self.deadline = loop.call_later(30, lambda: loop.create_task(self._incomplete(session)))
        try:
            if session.process is None or session.process.stdin is None:
                await self._incomplete(session)
                return
            async with session.server_stdin_lock:
                session.process.stdin.write((json.dumps(request) + "\n").encode())
                await asyncio.wait_for(session.process.stdin.drain(), timeout=5)
        except (OSError, RuntimeError, TimeoutError, AssertionError):
            # AssertionError: a second drain waiter on CPython <= 3.11; the catalog is simply not refreshed.
            await self._incomplete(session)

    async def inspect(self, session: CatalogRefreshSession, msg: dict) -> bool:
        """Return True only for proxy-owned responses, which must not reach the client."""
        if msg.get("method") == "notifications/tools/list_changed" and "id" not in msg:
            if self.request_id is not None:
                self.dirty = True
            else:
                await self._send(session)
            return False
        response_id = msg.get("id")
        if not isinstance(response_id, str) or not response_id.startswith(self.prefix):
            return False
        if response_id != self.request_id:
            return True  # A late response to a timed-out refresh is still private.
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            await self._incomplete(session)
            return True
        names = [t["name"] for t in result["tools"] if isinstance(t, dict) and isinstance(t.get("name"), str)]
        catalog = self.pages.accept(msg, names)
        if catalog is None:
            await self._send(session, result["nextCursor"])
            return True
        await session.handle_alerts(
            session.detectors.drift.check(catalog.names, complete=catalog.complete, fingerprints=catalog.fingerprints), session.log_file
        )
        if not catalog.complete:
            await self._incomplete(session)
            return True
        self._reset()
        if self.dirty:
            self.dirty = False
            await self._send(session)
        return True
