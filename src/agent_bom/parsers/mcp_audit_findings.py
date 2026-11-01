"""Project MCP audit evidence into the canonical finding stream."""

from __future__ import annotations

from typing import Any, cast

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.security import sanitize_sensitive_payload, sanitize_text


def enforcement_dict_to_finding(raw: dict) -> "Finding":
    """Promote a passive/full MCP enforcement row to the unified stream."""

    category = sanitize_text(raw.get("category", "injection") or "injection", max_len=80).lower()
    server_name = sanitize_text(raw.get("server_name", "unknown-server") or "unknown-server", max_len=200)
    tool_name = sanitize_text(raw.get("tool_name", "") or "", max_len=200)
    reason = sanitize_text(raw.get("reason", "MCP description security finding") or "", max_len=2_000)
    recommendation = sanitize_text(raw.get("recommendation", "") or "", max_len=1_000)
    severity = sanitize_text(raw.get("severity", "high") or "high", max_len=40)
    finding_type = FindingType.TOOL_DRIFT if "drift" in category else FindingType.INJECTION
    if category in {"over_permission", "schema_risk", "dangerous_combo", "cve_exposure", "tool_collision"}:
        finding_type = FindingType.PROMPT_SECURITY
    surface_name = sanitize_text(raw.get("surface_name") or tool_name or server_name, max_len=200)
    surface_type = raw.get("surface_type") or ("mcp_tool" if tool_name else "mcp_server")
    # A row naming no tool or surface (server-level capability combos) is about the server.
    if surface_type not in {"mcp_tool", "mcp_resource", "mcp_prompt", "mcp_server"} or not (raw.get("surface_name") or tool_name):
        surface_type = "mcp_server"
    identity = sanitize_text(raw.get("server_identity") or server_name, max_len=500)
    raw_evidence = raw.get("evidence")
    extra_evidence = dict(raw_evidence) if isinstance(raw_evidence, dict) else {}
    # Without a source rule id, the detector's reason is what tells two rows on one surface apart.
    extra_evidence.setdefault("rule_id", sanitize_text(f"{category}: {reason}", max_len=300))
    # A planted instruction in a descriptor is OWASP MCP03 Tool Poisoning and LLM01 Prompt Injection.
    poisoning = finding_type is FindingType.INJECTION and category in {
        "injection",
        "schema_injection",
        "resource_injection",
        "prompt_injection",
    }
    owasp_tags = sorted({*(extra_evidence.get("owasp_tags") or []), *(["LLM01"] if poisoning else [])})
    owasp_mcp_tags = sorted({*(extra_evidence.get("owasp_mcp_tags") or []), *(["MCP03"] if poisoning else [])})

    return Finding(
        finding_type=finding_type,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name=f"{surface_name} on {server_name}" if tool_name else server_name,
            asset_type=surface_type,
            identifier=sanitize_text(extra_evidence.get("asset_identifier") or "", max_len=500)
            or (
                f"{identity}:{surface_type}:{surface_name}"
                if raw.get("server_identity") or raw.get("surface_type")
                else f"{server_name}:{tool_name or category}"
            ),
        ),
        severity=severity,
        title=(
            f"MCP {category.replace('_', ' ')} on {surface_name}"
            + (
                f": {sanitize_text(extra_evidence.get('rule_id', ''))} / {sanitize_text(extra_evidence.get('property_name') or 'tool')}"
                if category == "schema_risk"
                else ""
            )
        ),
        description=reason,
        remediation_guidance=recommendation or None,
        owasp_tags=owasp_tags,
        owasp_mcp_tags=owasp_mcp_tags,
        evidence={
            **cast(dict[str, Any], sanitize_sensitive_payload(extra_evidence)),
            "server_identity": identity,
            "surface_type": surface_type,
            "category": category,
            "server_name": server_name,
            "tool_name": tool_name or None,
            "detector": "mcp_enforcement",
        },
        risk_score=9.0 if severity.lower() == "critical" else 8.0 if severity.lower() == "high" else 6.0,
        affected_agents=cast(list[str], sanitize_sensitive_payload(extra_evidence.get("affected_agents", []))),
        affected_servers=[server_name],
        exposed_tools=[tool_name] if tool_name and surface_type == "mcp_tool" else [],
    )
