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

from agent_bom.core.settings import env_bool, env_str
from agent_bom.mcp_errors import CODE_AUTH_FORBIDDEN
from agent_bom.mcp_tools.dispatch import _TOOL_ERROR_TYPES
from agent_bom.mcp_tools.request_identity import request_context

HOST_LOCAL_OPT_IN_ENV = "AGENT_BOM_MCP_ALLOW_HOST_LOCAL_TOOLS"

_ToolErrorBase: type[Exception] = _TOOL_ERROR_TYPES[0] if _TOOL_ERROR_TYPES else PermissionError  # type: ignore[assignment]


class HostLocalForbiddenError(_ToolErrorBase):  # type: ignore[misc,valid-type]
    """Raised as the tool's error; tools with broad handlers re-raise it unchanged."""


def shared_transport() -> bool:
    """True when the current call arrived over a shared (HTTP/SSE) transport."""
    context = request_context.get(None)
    if context is not None and getattr(context, "request", None) is not None:
        return True
    return env_str("AGENT_BOM_MCP_REMOTE_BIND").strip() == "1"


def host_local_allowed() -> bool:
    """True over stdio, or over a shared transport the operator opted in."""
    return not shared_transport() or env_bool(HOST_LOCAL_OPT_IN_ENV, False, on_invalid="default")


HOST_DISCOVERY_SKIPPED_WARNING = (
    "host agent discovery was skipped: this call arrived over HTTP or SSE, where the server host's agent configs are "
    f"not shared; pass config_path, or set {HOST_LOCAL_OPT_IN_ENV}=1 on a single-user server"
)


def host_discovery_allowed(*, explicit_target: bool, warnings: list[str]) -> bool:
    """Whether a no-path scan may discover this host's agents.

    Refused over a shared transport; when the call names its own target (image,
    SBOM or package) discovery is skipped with a warning instead of refusing.
    """
    if host_local_allowed():
        return True
    if not explicit_target:
        ensure_host_local_allowed()
    warnings.append(HOST_DISCOVERY_SKIPPED_WARNING)
    return False


def ensure_host_local_allowed() -> None:
    """Raise the forbidden tool error for a host-local read on a shared transport."""
    if host_local_allowed():
        return
    # The client prefixes the tool name; naming it here would trip the log
    # sanitizer, which redacts identifier-like tokens.
    message = (
        f"{CODE_AUTH_FORBIDDEN}: this tool reads the server host's local data and is off over HTTP and SSE; "
        f"set {HOST_LOCAL_OPT_IN_ENV}=1 to allow it"
    )
    raise HostLocalForbiddenError(message)
