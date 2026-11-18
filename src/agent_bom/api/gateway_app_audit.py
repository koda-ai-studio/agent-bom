"""Gateway audit tenant binding and fail-closed HTTP responses."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_auth import _extract_request_token
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.runtime.gateway_audit import GatewayAuditSinkBase
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_settings import GatewaySettings


def audit_unavailable_response(message_id: object, *, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {
                "code": -32003,
                "message": "Gateway audit persistence unavailable",
                "data": {
                    "reason": "Tool call was not executed because durable audit admission failed",
                    "policy_source": "audit_delivery",
                },
            },
        },
        status_code=503,
        headers=headers,
    )


def register_audit_handler(app: FastAPI) -> None:
    @app.exception_handler(GatewayAuditDeliveryUnavailableError)
    async def _audit_delivery_unavailable(request: Request, _exc: GatewayAuditDeliveryUnavailableError) -> JSONResponse:
        """Turn any pre-upstream audit outage into a stable fail-closed response."""

        if request.url.path.startswith("/mcp/"):
            record_gateway_relay(str(getattr(request.state, "gateway_upstream", "unknown")), "audit_unavailable")
            return audit_unavailable_response(getattr(request.state, "gateway_message_id", None))
        return JSONResponse(status_code=503, content={"detail": "Gateway audit persistence unavailable"})


async def bind_authenticated_audit_tenant(settings: GatewaySettings, request: Request, tenant_id: str, auth_method: str) -> None:
    sink = settings.audit_sink
    if not isinstance(sink, GatewayAuditSinkBase):
        return
    request_token = _extract_request_token(request) if auth_method == "api_key" else None
    await sink.bind_authenticated_tenant(tenant_id, request_token)
