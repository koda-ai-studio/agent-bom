"""Gate for MCP tools that read the server host's own workstation data.

Over stdio the MCP caller is the operator who launched the server, so reading
their coding-agent session history, browser extensions or auto-discovered MCP
client configs is the intended behaviour. Over streamable HTTP or SSE the same
server answers any authenticated caller, so those reads are refused unless the
operator opts in with ``AGENT_BOM_MCP_ALLOW_HOST_LOCAL_TOOLS``.

The transport is detected per request: the MCP SDK attaches the HTTP request to
the request context for both HTTP transports and leaves it unset for stdio and
in-memory sessions. A non-loopback bind (``AGENT_BOM_MCP_REMOTE_BIND``) is also
treated as shared, so the gate fails closed if a transport ever omits the
request object.
"""

from __future__ import annotations

import os

from agent_bom.mcp_errors import CODE_AUTH_FORBIDDEN
from agent_bom.mcp_server_runtime import _TOOL_ERROR_TYPES

HOST_LOCAL_OPT_IN_ENV = "AGENT_BOM_MCP_ALLOW_HOST_LOCAL_TOOLS"
_TRUTHY = {"1", "true", "yes", "on"}


def shared_transport() -> bool:
    """True when the current call arrived over a shared (HTTP/SSE) transport."""
    from agent_bom.mcp_tools.request_identity import request_context

    context = request_context.get(None)
    if context is not None and getattr(context, "request", None) is not None:
        return True
    return os.environ.get("AGENT_BOM_MCP_REMOTE_BIND", "").strip() == "1"


def ensure_host_local_allowed() -> None:
    """Raise the forbidden tool error for a host-local read on a shared transport."""
    if not shared_transport():
        return
    if os.environ.get(HOST_LOCAL_OPT_IN_ENV, "").strip().lower() in _TRUTHY:
        return
    # The client prefixes the tool name; naming it here would trip the log
    # sanitizer, which redacts identifier-like tokens.
    message = (
        f"{CODE_AUTH_FORBIDDEN}: this tool reads the server host's local data and is off over HTTP and SSE; "
        f"set {HOST_LOCAL_OPT_IN_ENV}=1 to allow it"
    )
    if _TOOL_ERROR_TYPES:
        raise _TOOL_ERROR_TYPES[0](message)
    raise PermissionError(message)
