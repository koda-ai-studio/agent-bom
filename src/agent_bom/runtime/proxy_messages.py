"""Bounded JSON-RPC frames and trace metadata."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from agent_bom.runtime.proxy_tracing import (
    _extract_jsonrpc_trace_meta as _extract_jsonrpc_trace_meta,
)
from agent_bom.runtime.proxy_tracing import (
    _proxy_request_headers as _proxy_request_headers,
)
from agent_bom.runtime.proxy_tracing import (
    _stitch_jsonrpc_trace_meta as _stitch_jsonrpc_trace_meta,
)

_MAX_MESSAGE_BYTES = 2 * 1024 * 1024


async def _read_bounded_line(reader: asyncio.StreamReader, *, max_bytes: int = _MAX_MESSAGE_BYTES) -> bytes | None:
    """Read one newline-delimited message without accepting an oversized line."""
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        return exc.partial or b""
    except asyncio.LimitOverrunError as exc:
        if exc.consumed:
            await reader.readexactly(exc.consumed)
        try:
            await reader.readuntil(b"\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            pass
        return None
    except ValueError:
        while True:
            chunk = await reader.read(1)
            if not chunk or b"\n" in chunk:
                break
        return None

    if len(line) > max_bytes:
        return None
    return line


def parse_jsonrpc(line: str) -> Optional[dict]:
    """Parse a JSON-RPC message from a single line.

    Returns the parsed dict or None if the line is not valid JSON-RPC.
    """
    line = line.strip()
    if not line:
        return None
    try:
        msg = json.loads(line)
        if isinstance(msg, dict) and ("jsonrpc" in msg or "method" in msg or "result" in msg):
            return msg
        return None
    except (json.JSONDecodeError, TypeError):
        return None


def is_tools_call(msg: dict) -> bool:
    """Check if a JSON-RPC message is a tools/call request."""
    return msg.get("method") == "tools/call"


_POLICY_GATED_METHODS = {
    "prompts/get",
    "resources/read",
    "sampling/createMessage",
    "subscriptions/listen",
}


def policy_subject_from_message(msg: dict) -> tuple[str, dict] | None:
    """Return the policy subject and arguments for gated JSON-RPC methods."""
    if is_tools_call(msg):
        return extract_tool_name(msg) or "unknown", extract_tool_arguments(msg)

    method = msg.get("method")
    if not isinstance(method, str):
        return None
    if method not in _POLICY_GATED_METHODS and not method.startswith("mcp_extension/"):
        return None

    params = msg.get("params", {})
    if isinstance(params, dict):
        return method, params
    return method, {"params": params}


def is_tools_list_response(msg: dict, request_id: Optional[int | str] = None) -> bool:
    """Check if a JSON-RPC message is a tools/list response."""
    if "result" not in msg:
        return False
    result = msg.get("result", {})
    if isinstance(result, dict) and "tools" in result:
        return True
    return False


def extract_tool_name(msg: dict) -> Optional[str]:
    """Extract the tool name from a tools/call request.

    A caller controls these types. A non-dict ``params`` or a non-string
    ``name`` used to raise ``AttributeError`` out of the relay: a 500 with no
    policy decision, no audit event, and no ledger record. Ill-typed is not
    unnameable — it resolves to no name, and the caller is still governed.
    """
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) else None


def extract_tool_arguments(msg: dict) -> dict:
    """Extract tool arguments from a tools/call request.

    Coerces a caller-supplied non-dict to an empty mapping for the same reason
    as :func:`extract_tool_name`.
    """
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return {}
    arguments = params.get("arguments", {})
    return arguments if isinstance(arguments, dict) else {}


def extract_declared_tools(msg: dict) -> list[str]:
    """Extract declared tool names from a tools/list response."""
    result = msg.get("result", {})
    tools = result.get("tools", [])
    return [t.get("name", "") for t in tools if isinstance(t, dict)]


def make_error_response(request_id: int | str | None, code: int, message: str) -> dict:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def undeclared_tool_block_reason(block_undeclared: bool, declared_tools: set[str], tool_name: str) -> str | None:
    """Return a hard-block reason for undeclared tools when enforcement is on."""
    if not block_undeclared:
        return None
    if tool_name in declared_tools:
        return None
    if declared_tools:
        return f"Tool '{tool_name}' not in declared tools/list"
    return f"Tool '{tool_name}' blocked because no tools/list declarations are available"


def _sanitize_for_log(value: object) -> str:
    return str(value).replace("\r", "").replace("\n", "")
