"""``audit_integrity`` MCP tool: verify the control-plane audit chain through its REST route."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

from agent_bom.api.route_offload import call_route as _call_route
from agent_bom.mcp_errors import CODE_UNSUPPORTED_BACKEND, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


# Top-level modules shipped only by the ``agent-bom[api]`` extra.
_API_EXTRA_MODULES = frozenset({"fastapi", "uvicorn", "sse_starlette", "zstandard"})


async def audit_integrity_impl(
    *,
    tenant_id: str = "default",
    limit: int = 1000,
    include_runtime: bool = True,
    _truncate_response,
) -> str:
    """Implementation of the audit_integrity tool."""
    try:
        from agent_bom.api.routes.enterprise import audit_integrity

        bounded_limit = max(1, min(int(limit), 10_000))
        payload = await _call_route(
            audit_integrity,
            SimpleNamespace(state=SimpleNamespace(tenant_id=resolve_mcp_tool_tenant_id(tenant_id), actor="mcp-operator")),
            limit=bounded_limit,
            include_runtime=include_runtime,
        )
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except ModuleNotFoundError as exc:
        if (exc.name or "").split(".")[0] not in _API_EXTRA_MODULES:
            logger.exception("MCP audit integrity error")
            return json.dumps({"error": sanitize_error(exc)})
        return mcp_error_json(
            CODE_UNSUPPORTED_BACKEND,
            "audit_integrity verifies the control-plane audit chain and requires the API extra: install agent-bom[api].",
            details={"missing_module": exc.name, "install": "pip install 'agent-bom[api]'"},
        )
    except Exception as exc:
        logger.exception("MCP audit integrity error")
        return json.dumps({"error": sanitize_error(exc)})
