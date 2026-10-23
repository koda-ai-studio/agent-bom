"""MCP descriptor audit orchestration; discovery never invokes tools."""

from __future__ import annotations

import json
import logging

from agent_bom import discovery, mcp_introspect
from agent_bom.discovery.agent_permission_posture import evaluate_agent_permission_posture
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
from agent_bom.scanners.mcp_audit import audit_mcp_agents
from agent_bom.security import sanitize_error, sanitize_sensitive_payload

logger = logging.getLogger(__name__)


def tool_risk_assessment_impl(
    *,
    config_path: str | None = None,
    timeout: float = 10.0,
    allow_command_execution: bool = False,
    live: bool = True,
    expected_capabilities: list[str] | None = None,
    _authenticated_actor: str = "",
    _safe_path,
    _truncate_response,
) -> str:
    """Implementation of the tool_risk_assessment tool."""
    from agent_bom.mcp_server_runtime import resolve_tool_path

    resolved_config_path = str(resolve_tool_path(_safe_path, config_path, argument="config_path")) if config_path else None
    try:
        agents = discovery.discover_all(project_dir=resolved_config_path)
        servers = [s for a in agents for s in a.mcp_servers if s.is_mcp_surface]
        permission_findings = [f.to_dict() for f in evaluate_agent_permission_posture(agents)]
        if not servers:
            payload = {"status": "no_servers_found", "servers": [], "agent_permission_findings": permission_findings}
            return _truncate_response(json.dumps(sanitize_sensitive_payload(payload), indent=2))

        report = (
            mcp_introspect.introspect_servers_sync(servers, timeout=timeout, allow_stdio=allow_command_execution)
            if live
            else mcp_introspect.IntrospectionReport()
        )
        audit = audit_mcp_agents(agents, introspection_report=report if live else None, expected_capabilities=expected_capabilities)
        results = [r.to_dict(include_runtime_objects=True) for r in report.results]
        summary = {
            "total_servers": len(servers),
            "live_requested": live,
            "successful": report.successful,
            "failed": report.failed,
            "critical_or_high": sum(1 for r in report.results if r.capability_risk_level in ("critical", "high")),
            "max_capability_risk_score": max((r.capability_risk_score for r in report.results), default=0.0),
            "command_execution_allowed": allow_command_execution,
        }
        return _truncate_response(
            json.dumps(
                sanitize_sensitive_payload(
                    {
                        "summary": summary,
                        "servers": results,
                        "warnings": report.warnings,
                        "audit": audit.to_dict(),
                        "authentication_findings": [f.to_dict() for f in evaluate_mcp_auth_posture(agents)],
                        "agent_permission_findings": permission_findings,
                    }
                ),
                indent=2,
            )
        )
    except Exception as exc:
        logger.error("MCP audit failed")
        return json.dumps({"error": sanitize_error(exc, generic=True)})
