"""Bounded MCP wire semantics shared by gateway transports."""

from __future__ import annotations

from typing import Any

MODERN_PROTOCOL = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"


def request_headers(message: dict[str, Any], supplied: dict[str, str]) -> dict[str, str]:
    """Derive protocol headers from the authoritative JSON body."""
    headers = {
        k: v
        for k, v in supplied.items()
        if k.lower() not in {"content-type", "accept", "mcp-method", "mcp-name", "mcp-protocol-version", "mcp-session-id"}
    }
    headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    method = message.get("method")
    if not isinstance(method, str) or not method or any(ord(c) < 33 or ord(c) > 126 for c in method):
        raise ValueError("Invalid MCP request method")
    headers["Mcp-Method"] = method
    params = message.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("Invalid MCP request parameters")
    key = "uri" if method in {"resources/read"} else "name"
    if method in {"tools/call", "prompts/get", "resources/read"}:
        name = params.get(key)
        if not isinstance(name, str) or not name or len(name) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError("Invalid MCP request name")
        from mcp.shared.inbound import encode_header_value

        headers["Mcp-Name"] = encode_header_value(name)
    meta = params.get("_meta", {})
    if isinstance(meta, dict) and VERSION_KEY in meta:
        version = meta[VERSION_KEY]
        if version != MODERN_PROTOCOL:
            raise ValueError("Unsupported MCP protocol version")
        headers["Mcp-Protocol-Version"] = version
    return headers


def validate_response(message: dict[str, Any], response: Any) -> dict[str, Any]:
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or type(response.get("id")) is not type(message.get("id"))
        or response.get("id") != message.get("id")
        or ("result" in response) == ("error" in response)
    ):
        raise ValueError("Invalid MCP upstream response envelope")
    if "result" in response and not isinstance(response["result"], dict):
        raise ValueError("Invalid MCP result envelope")
    error = response.get("error")
    if "error" in response and (
        not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str)
    ):
        raise ValueError("Invalid MCP error envelope")
    result = response.get("result")
    if isinstance(result, dict) and result.get("resultType", "complete") not in {"complete", "input_required"}:
        raise ValueError("Unsupported MCP response result type")
    return response


def inspection_arguments(message: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    """Include MRTR input responses in DLP without changing tool authorization arguments."""
    params = message.get("params")
    if isinstance(params, dict) and "inputResponses" in params:
        return {"arguments": arguments, "inputResponses": params["inputResponses"]}
    return arguments


def validate_request_headers(message: dict[str, Any], headers: Any) -> None:
    """Reject misleading routing headers before policy or upstream effects."""
    params = message.get("params") or {}
    meta = params.get("_meta", {}) if isinstance(params, dict) else {}
    if (not isinstance(meta, dict) or meta.get(VERSION_KEY) != MODERN_PROTOCOL) and headers.get("Mcp-Protocol-Version") != MODERN_PROTOCOL:
        return
    if not isinstance(meta, dict) or meta.get(VERSION_KEY) != MODERN_PROTOCOL:
        raise ValueError("MCP protocol version metadata is required")
    expected = request_headers(message, {})
    for key in ("Mcp-Method", "Mcp-Name", "Mcp-Protocol-Version"):
        if headers.get(key) != expected.get(key):
            raise ValueError("MCP header does not match request body")
    if not isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict):
        raise ValueError("MCP client capabilities are required")


MAX_TOOL_CATALOG_PAGES = 20


async def parameter_headers(transport: Any, target: Any, message: dict[str, Any], headers: dict[str, str]) -> dict[str, str]:
    """Resolve x-mcp-header mappings using an authenticated, uncached listing.

    No catalog is shared between tenants or credentials. Discovery is bounded
    and read-only; a missing/oversized catalog fails before the tool call.
    """
    from mcp.shared.inbound import mcp_param_headers, x_mcp_header_map

    from agent_bom.runtime.gateway_relay_contract import RelayForwardRequest

    params = message.get("params", {})
    meta = params.get("_meta", {}) if isinstance(params, dict) else {}
    if message.get("method") != "tools/call" or not isinstance(meta, dict) or meta.get(VERSION_KEY) != MODERN_PROTOCOL:
        return {}
    cursor = None
    seen = set()
    for page in range(MAX_TOOL_CATALOG_PAGES):
        listing_params: dict[str, Any] = {"_meta": meta}
        if cursor is not None:
            listing_params["cursor"] = cursor
        listing = await transport.forward(
            RelayForwardRequest(
                upstream=target,
                message={"jsonrpc": "2.0", "id": f"gateway-schema-{page}", "method": "tools/list", "params": listing_params},
                headers=headers,
            )
        )
        result = listing.message.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise ValueError("MCP tool catalog unavailable")
        for tool in result["tools"]:
            if isinstance(tool, dict) and tool.get("name") == params.get("name"):
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise ValueError("MCP tool arguments must be an object")
                return mcp_param_headers(x_mcp_header_map(tool.get("inputSchema", {})), arguments)
        cursor = result.get("nextCursor")
        if cursor is None:
            raise ValueError("MCP tool is absent from the authenticated catalog")
        if not isinstance(cursor, str) or cursor in seen:
            raise ValueError("Invalid MCP catalog pagination")
        seen.add(cursor)
    raise ValueError("MCP catalog pagination exceeds limit")


MAX_SESSION_ID_LENGTH = 512


def validate_session_id(value: Any) -> str:
    """Accept a server-issued ``Mcp-Session-Id`` only as 1-512 visible ASCII characters."""
    if not isinstance(value, str) or not value or len(value) > MAX_SESSION_ID_LENGTH or any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
        raise ValueError("Invalid MCP session id from upstream")
    return value


async def sse_messages(response: Any, max_bytes: int, *, max_event_bytes: int | None = None, max_events: int | None = None):
    """Bound bytes before line/event decoding; ignore comments and SSE retry hints.

    ``max_event_bytes`` caps one event (and any unterminated line) and
    ``max_events`` caps how many events a single response may carry.
    """
    buffer = b""
    data: list[str] = []
    event_bytes = 0
    events = 0
    consumed = 0
    async for chunk in response.aiter_bytes():
        consumed += len(chunk)
        if consumed > max_bytes:
            raise ValueError("MCP upstream response exceeds size limit")
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("utf-8", errors="strict")
            if line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
                event_bytes += len(raw)
                if max_event_bytes is not None and event_bytes > max_event_bytes:
                    raise ValueError("MCP upstream stream event exceeds size limit")
            elif not line and data:
                import json

                events += 1
                if max_events is not None and events > max_events:
                    raise ValueError("MCP upstream stream has too many events")
                yield json.loads("\n".join(data)), consumed
                data.clear()
                event_bytes = 0
        if max_event_bytes is not None and len(buffer) > max_event_bytes:
            raise ValueError("MCP upstream stream event exceeds size limit")
    if data or buffer.strip():
        raise ValueError("Incomplete MCP event stream")
