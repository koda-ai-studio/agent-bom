"""Assemble paginated MCP ``tools/list`` responses into one catalog.

A server may split its catalog across pages linked by ``nextCursor``. Drift
must be judged on the whole catalog, never on a single page. Pagination limits
match the gateway's catalog discovery (:mod:`agent_bom.runtime.mcp_protocol`):
at most ``MAX_TOOL_CATALOG_PAGES`` pages, string cursors, no repeated cursor.
A listing that breaks those rules is reported as incomplete.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.runtime.mcp_protocol import MAX_TOOL_CATALOG_PAGES

RequestId = int | str
_MAX_TRACKED_REQUESTS = 256


@dataclass(frozen=True)
class ToolCatalog:
    """A finished listing; ``complete`` is False when pagination was capped or invalid."""

    names: list[str]
    complete: bool


@dataclass
class ToolCatalogPages:
    """Per-session accumulator for one in-flight paginated ``tools/list``."""

    names: list[str] = field(default_factory=list)
    pages: int = 0
    seen_cursors: set[str] = field(default_factory=set)
    discarding: bool = False
    first_page_ids: set[RequestId] = field(default_factory=set)
    continuation_ids: set[RequestId] = field(default_factory=set)

    def note_request(self, msg: dict) -> None:
        """Remember whether a client ``tools/list`` request starts a listing or continues one."""
        request_id = msg.get("id")
        if not isinstance(request_id, (int, str)):
            return
        params = msg.get("params")
        has_cursor = isinstance(params, dict) and params.get("cursor") is not None
        if len(self.first_page_ids) + len(self.continuation_ids) >= _MAX_TRACKED_REQUESTS:
            self.first_page_ids.clear()
            self.continuation_ids.clear()
        (self.continuation_ids if has_cursor else self.first_page_ids).add(request_id)

    def _reset(self) -> None:
        self.names = []
        self.pages = 0
        self.seen_cursors = set()

    def _finish(self, complete: bool) -> ToolCatalog:
        catalog = ToolCatalog(names=self.names, complete=complete)
        self._reset()
        self.discarding = not complete
        return catalog

    def accept(self, msg: dict, names: list[str]) -> ToolCatalog | None:
        """Add one response page; return the catalog once the listing ends, else ``None``."""
        request_id = msg.get("id")
        result = msg.get("result")
        cursor = result.get("nextCursor") if isinstance(result, dict) else None
        is_first = request_id in self.first_page_ids
        is_continuation = request_id in self.continuation_ids
        self.first_page_ids.discard(request_id)  # type: ignore[arg-type]
        self.continuation_ids.discard(request_id)  # type: ignore[arg-type]
        if is_first:
            self._reset()
            self.discarding = False
        if self.discarding:
            self.discarding = cursor is not None
            return None
        if is_continuation and self.pages == 0:
            return None
        self.names.extend(names)
        self.pages += 1
        if cursor is None:
            return self._finish(complete=True)
        if not isinstance(cursor, str) or cursor in self.seen_cursors or self.pages >= MAX_TOOL_CATALOG_PAGES:
            return self._finish(complete=False)
        self.seen_cursors.add(cursor)
        return None


async def fetch_tool_catalog(fetch_page: Callable[[str | None], Awaitable[Any]]) -> ToolCatalog:
    """Fetch a whole ``tools/list`` catalog by following ``nextCursor``.

    ``fetch_page(cursor)`` returns one JSON-RPC response. A page without a tool
    list, a non-string or repeated cursor, or the page cap ends the listing as
    incomplete with the names gathered so far.
    """
    names: list[str] = []
    seen: set[str] = set()
    cursor: str | None = None
    for _ in range(MAX_TOOL_CATALOG_PAGES):
        response = await fetch_page(cursor)
        result = response.get("result") if isinstance(response, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return ToolCatalog(names, complete=False)
        names.extend(t["name"] for t in result["tools"] if isinstance(t, dict) and isinstance(t.get("name"), str))
        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            return ToolCatalog(names, complete=True)
        if not isinstance(next_cursor, str) or next_cursor in seen:
            return ToolCatalog(names, complete=False)
        seen.add(next_cursor)
        cursor = next_cursor
    return ToolCatalog(names, complete=False)


async def fetch_http_tool_catalog(client: Any, list_url: str, headers: dict[str, str]) -> ToolCatalog:
    """Page a remote server's ``tools/list`` over HTTP POST; HTTP errors propagate."""

    async def fetch_page(cursor: str | None) -> Any:
        params = {"cursor": cursor} if cursor is not None else {}
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}
        response = await client.post(list_url, json=message, headers=headers)
        response.raise_for_status()
        return response.json()

    return await fetch_tool_catalog(fetch_page)
