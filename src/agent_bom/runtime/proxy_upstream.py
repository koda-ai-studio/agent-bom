"""Upstream transports for ``agent-bom proxy --url``.

``StreamableHttpUpstream`` speaks MCP Streamable HTTP on the one URL the
operator gave, through the gateway's bounded forward
(:func:`agent_bom.runtime.gateway_relay_contract.forward_jsonrpc_http`).
``CompatHttpUpstream`` keeps the older ``/tools/list``, ``/tools/call`` and
``/message`` endpoints for servers that still need them
(``--compat-endpoints``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from agent_bom.runtime.gateway_relay_contract import forward_jsonrpc_http
from agent_bom.runtime.mcp_protocol import validate_session_id
from agent_bom.runtime.tool_catalog_pages import ToolCatalog, fetch_http_tool_catalog, fetch_tool_catalog

logger = logging.getLogger("agent_bom.proxy")

MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PROXY_SSE_EVENT_BYTES = 1024 * 1024
MAX_PROXY_SSE_EVENTS = 256
PROXY_RESPONSE_DEADLINE_SECONDS = 60.0
PROXY_SESSION_CLOSE_SECONDS = 5.0

_SAFE_REASON_PREFIXES = ("MCP ", "Invalid MCP", "Unsupported MCP", "Incomplete MCP")


class UpstreamResponseRejectedError(Exception):
    """The upstream answer broke a bound or the MCP wire contract; the reason never carries body content."""


def _safe_reason(exc: Exception) -> str:
    text = str(exc)
    return text if text.startswith(_SAFE_REASON_PREFIXES) else "Malformed MCP upstream response"


def upstream_error_message(exc: Exception) -> str:
    """Client-facing upstream failure text; never includes response bodies or headers."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"Upstream server error: {exc.response.status_code}"
    if isinstance(exc, UpstreamResponseRejectedError):
        return f"Upstream response rejected: {exc}"
    return "Upstream connection error"


class _Upstream:
    # discover_at_start: whether tools/list can run before the client's
    # initialize. Streamable HTTP servers only answer it inside an initialized
    # session, so the proxy discovers before the first tools/call instead.
    discover_at_start = True
    reports_pass_through_errors = False

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()


class CompatHttpUpstream(_Upstream):
    """Legacy per-purpose endpoints, unchanged from earlier releases."""

    def __init__(self, client: Any, url: str) -> None:
        self.client = client
        self.base_url = url.rstrip("/")

    async def tool_catalog(self, headers: dict[str, str]) -> ToolCatalog:
        return await fetch_http_tool_catalog(self.client, self.base_url + "/tools/list", headers)

    async def pass_through(self, message: dict, headers: dict[str, str]) -> dict | None:
        response = await self.client.post(self.base_url + "/message", json=message, timeout=30, headers=headers)
        return response.json()

    async def forward(self, message: dict, headers: dict[str, str], *, is_tool_call: bool) -> dict:
        path = "/tools/call" if is_tool_call else "/message"
        response = await self.client.post(self.base_url + path, json=message, timeout=30, headers=headers)
        response.raise_for_status()
        return response.json()


class StreamableHttpUpstream(_Upstream):
    """One MCP endpoint, a server-issued session and bounded JSON/SSE answers."""

    discover_at_start = False
    reports_pass_through_errors = True

    def __init__(self, client: Any, url: str) -> None:
        self.client = client
        self.url = url
        self.session_id: str | None = None
        self._catalog_requests = 0

    async def send(self, message: dict, headers: dict[str, str]) -> dict | None:
        """POST one JSON-RPC message; returns the correlated response, or None for a notification."""
        try:
            result = await asyncio.wait_for(
                forward_jsonrpc_http(
                    upstream_url=self.url,
                    message=message,
                    headers=headers,
                    client=self.client,
                    max_bytes=MAX_PROXY_RESPONSE_BYTES,
                    session_id=self.session_id,
                    max_event_bytes=MAX_PROXY_SSE_EVENT_BYTES,
                    max_events=MAX_PROXY_SSE_EVENTS,
                ),
                timeout=PROXY_RESPONSE_DEADLINE_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise UpstreamResponseRejectedError("MCP upstream response deadline exceeded") from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404 and self.session_id is not None:
                self.session_id = None
                raise UpstreamResponseRejectedError("MCP upstream session terminated; the client must re-initialize") from exc
            raise
        except ValueError as exc:
            raise UpstreamResponseRejectedError(_safe_reason(exc)) from exc
        if message.get("method") == "initialize" and result.session_id is not None:
            try:
                self.session_id = validate_session_id(result.session_id)
            except ValueError as exc:
                raise UpstreamResponseRejectedError(str(exc)) from exc
        return result.message or None

    async def tool_catalog(self, headers: dict[str, str]) -> ToolCatalog:
        async def fetch_page(cursor: str | None) -> Any:
            self._catalog_requests += 1
            params = {"cursor": cursor} if cursor is not None else {}
            message = {"jsonrpc": "2.0", "id": f"agent-bom-proxy-tools-list-{self._catalog_requests}", "method": "tools/list"}
            return await self.send({**message, "params": params}, headers)

        return await fetch_tool_catalog(fetch_page)

    async def pass_through(self, message: dict, headers: dict[str, str]) -> dict | None:
        return await self.send(message, headers)

    async def forward(self, message: dict, headers: dict[str, str], *, is_tool_call: bool) -> dict:
        response = await self.send(message, headers)
        if response is None:
            raise UpstreamResponseRejectedError("MCP request acknowledged without a response")
        return response

    async def close(self) -> None:
        """Ask the server to end the session; 405 (not supported) and failures are ignored."""
        if self.session_id is None:
            return
        try:
            await self.client.request("DELETE", self.url, headers={"Mcp-Session-Id": self.session_id}, timeout=PROXY_SESSION_CLOSE_SECONDS)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Streamable HTTP proxy: session close failed: %s", type(exc).__name__)
        finally:
            self.session_id = None


def build_proxy_upstream(client: Any, url: str, compat_endpoints: bool) -> CompatHttpUpstream | StreamableHttpUpstream:
    return CompatHttpUpstream(client, url) if compat_endpoints else StreamableHttpUpstream(client, url)


__all__ = [
    "MAX_PROXY_RESPONSE_BYTES",
    "MAX_PROXY_SSE_EVENTS",
    "MAX_PROXY_SSE_EVENT_BYTES",
    "PROXY_RESPONSE_DEADLINE_SECONDS",
    "CompatHttpUpstream",
    "StreamableHttpUpstream",
    "UpstreamResponseRejectedError",
    "build_proxy_upstream",
    "upstream_error_message",
]
