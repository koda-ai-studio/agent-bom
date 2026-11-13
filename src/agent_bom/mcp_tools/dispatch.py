"""Tool-call outcome helpers shared by the MCP dispatcher and the tool modules.

Kept free of ``mcp_server_runtime`` imports so the tool modules can use them
without an import cycle; ``mcp_server_runtime`` re-exports the public names.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_PATH
from agent_bom.mcp_server_scan import McpScanValidationError
from agent_bom.security import sanitize_error, sanitize_log_label


class ToolErrorPayload(str):
    """A JSON tool payload that reports a failed or incomplete call.

    It is an ordinary JSON string for callers that only read text; tools that
    return a ``CallToolResult`` map it to ``is_error=True``.
    """


try:
    from mcp.server.mcpserver.exceptions import ToolError as _FastMCPToolError
except ModuleNotFoundError:  # pragma: no cover - base CLI installs do not include MCP extras
    _TOOL_ERROR_TYPES: tuple[type[BaseException], ...] = ()
else:
    _TOOL_ERROR_TYPES = (_FastMCPToolError,)


def resolve_tool_path(safe_path_fn: Callable[[str], Path], value: str, *, argument: str) -> Path:
    """Resolve a tool path argument or raise the structured invalid-path tool error.

    The error text matches the ``scan`` tool's rejection
    (``AGENTBOM_MCP_VALIDATION_INVALID_PATH: ... (argument: <name>)``) so every
    path-taking tool reports a sandbox rejection the same way, as ``isError``.
    """
    try:
        return safe_path_fn(value)
    except ValueError as exc:
        error = McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument=argument)
        if _TOOL_ERROR_TYPES:
            raise _TOOL_ERROR_TYPES[0](str(error)) from exc
        raise error from exc


def raise_scan_tool_failure(exc: Exception, log: logging.Logger) -> NoReturn:
    """Raise a failed scan as a tool error: a refused input is the caller's error and logs no traceback."""
    error_type: type[BaseException] = _TOOL_ERROR_TYPES[0] if _TOOL_ERROR_TYPES else RuntimeError
    if isinstance(exc, McpScanValidationError):
        raise error_type(str(exc)) from None
    log.exception("MCP tool error")
    raise error_type(sanitize_error(exc)) from exc


_ERROR_SNIFF_MAX_CHARS = 256 * 1024


def _payload_error(text: str) -> str | None:
    stripped = text.lstrip()
    if not stripped.startswith("{") or len(stripped) > _ERROR_SNIFF_MAX_CHARS or '"error"' not in stripped:
        return None
    try:
        doc = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    error = doc.get("error")
    if isinstance(error, dict):
        message = str(error.get("message") or "")
        code = str(error.get("code") or "")
        combined = f"{code}: {message}" if code and message else code or message
        return combined or "error payload"
    if isinstance(error, str) and error:
        return error
    return None


def tool_result_error(result: object) -> str | None:
    """Return the error a tool reported in its *returned* payload, if any.

    Tools often catch their own exceptions and return ``{"error": "..."}`` or an
    :func:`agent_bom.mcp_errors.mcp_error_json` envelope instead of raising. The
    dispatcher uses this to log and count those calls as failures.
    """
    if getattr(result, "is_error", False) is True:
        return "error result"
    if not isinstance(result, str):
        return None
    found = _payload_error(result)
    if found is None and isinstance(result, ToolErrorPayload):
        return "error payload"
    return found


def _single_text(content: Any) -> str | None:
    if not isinstance(content, list) or len(content) != 1:
        return None
    item = content[0]
    kind = item.get("type") if isinstance(item, dict) else getattr(item, "type", None)
    text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
    return text if kind == "text" and isinstance(text, str) else None


def flag_error_result(result: Any) -> Any:
    """Mark a ``tools/call`` result ``isError`` when its payload reports an error.

    Tools return their JSON text as ``str``; the SDK wraps it with
    ``isError: false`` and the ``ToolErrorPayload`` type is gone by then. The
    same envelope check :func:`tool_result_error` uses for metrics decides here,
    so a rate limit, refusal or caught failure is an error on the wire too.
    """
    if isinstance(result, dict):
        if result.get("isError") is True:
            return result
        text = _single_text(result.get("content"))
        return {**result, "isError": True} if text is not None and _payload_error(text) is not None else result
    if getattr(result, "is_error", None) is not False:
        return result
    text = _single_text(getattr(result, "content", None))
    if text is None or _payload_error(text) is None:
        return result
    return result.model_copy(update={"is_error": True})


async def flag_tool_error_results(ctx: Any, call_next: Any) -> Any:
    """MCP middleware applying :func:`flag_error_result` to every ``tools/call``, in every transport."""
    result = await call_next(ctx)
    return flag_error_result(result) if getattr(ctx, "method", None) == "tools/call" else result


def record_completion(
    tool_name: str,
    result: object,
    elapsed_ms: int,
    request_meta: dict[str, Any],
    log_caller: str,
    record_tool_metric_fn: Callable[..., None],
    record_tool_request_fn: Callable[..., None],
    logger,
) -> None:
    """Record a returned call as ok, or as an error when its payload reports one."""
    reported_error = tool_result_error(result)
    error = (sanitize_log_label(reported_error, max_len=200) or "-") if reported_error is not None else None
    record_tool_metric_fn(tool_name, elapsed_ms=elapsed_ms, success=error is None, error=error)
    record_tool_request_fn(
        tool_name,
        caller=request_meta["caller"],
        client_id=request_meta["client_id"],
        request_id=request_meta["request_id"],
        status="ok" if error is None else "error",
        elapsed_ms=elapsed_ms,
        error=error,
    )
    if error is None:
        logger.info("mcp tool ok: %s caller=%s (%dms)", tool_name, log_caller, elapsed_ms)
    else:
        logger.warning("mcp tool returned error: %s caller=%s (%dms) (%s)", tool_name, log_caller, elapsed_ms, error)
