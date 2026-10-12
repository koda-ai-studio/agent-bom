"""Metadata projections of native vendor observations into the shared span shape.

Native scope is a source claim, not an authorization boundary. Importers must
bind it to the authenticated connection before persisting or correlating it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _nanos(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            return ""
        delta = moment - datetime(1970, 1, 1, tzinfo=timezone.utc)
        nanos = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
        return str(nanos) if 0 < nanos < 2**64 else ""
    except (ValueError, OverflowError):
        return ""


def native_span(row: dict[str, Any], *, provider: str, include_content: bool) -> dict[str, Any] | None:
    """Keep physical parentage and native kind without inventing tool calls."""
    name = _text(row.get("name")).strip()
    if not name:
        return None
    lf = provider == "langfuse"
    native_type = _text(row.get("type" if lf else "run_type"))
    # Compatibility for older tool-only connector payloads. Retain the missing
    # native type explicitly; it is not a vendor assertion of execution kind.
    tool = native_type.lower() == "tool" or not native_type
    extra = row.get("extra")
    raw_metadata = row.get("metadata") if lf else extra.get("metadata") if isinstance(extra, dict) else None
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
    attrs: dict[str, str] = {
        "agent_bom.trace_provider": provider,
        "agent_bom.native_name": name,
        "agent_bom.native_type": native_type or "unknown",
        "agent_bom.type_basis": "native" if native_type else "legacy_tool_adapter",
    }
    if tool:
        attrs["tool.name"] = name
    for key, value in {
        "agent_bom.inventory_node_id": metadata.get("agent_bom.inventory_node_id"),
        "agent_bom.inventory_scan_id": metadata.get("agent_bom.inventory_scan_id"),
        "agent_bom.inventory_generation": metadata.get("agent_bom.inventory_generation"),
        "mcp.server": metadata.get("server") or metadata.get("mcp_server"),
        "package.name": metadata.get("package") or metadata.get("dependency"),
        "agent_bom.native_project_id": row.get("projectId" if lf else "session_id"),
        "agent_bom.native_environment": row.get("environment") if lf else metadata.get("environment"),
        "agent_bom.native_session_id": row.get("sessionId") if lf else None,
    }.items():
        if isinstance(value, str) and value:
            attrs[key] = value
    if lf and isinstance(row.get("isRootObservation"), bool):
        attrs["agent_bom.logical_root"] = "true" if row["isRootObservation"] else "false"
    if include_content:
        output = row.get("output" if lf else "outputs")
        if output is not None:
            attrs["tool.output" if tool else "gen_ai.completion"] = str(output)
    start = _nanos(row.get("startTime" if lf else "start_time"))
    end = _nanos(row.get("endTime" if lf else "end_time"))
    failed = str(row.get("level") or "").upper() == "ERROR" if lf else bool(row.get("error"))
    span: dict[str, Any] = {
        "traceId": _text(row.get("traceId") or row.get("trace_id")),
        "spanId": _text(row.get("id")),
        "parentSpanId": _text(row.get("parentObservationId" if lf else "parent_run_id")),
        "name": f"adk.tool.{name}" if tool else f"{provider}.{native_type.lower()}.{name}",
        "status": {"code": 2 if failed else 0},
        "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attrs.items()],
    }
    # An end timestamp establishes completion, not a successful external effect.
    # Retain the vendor status separately rather than asserting OTLP OK.
    if start:
        span["startTimeUnixNano"] = start
    if end:
        span["endTimeUnixNano"] = end
    return span
