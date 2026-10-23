"""Read-only MCP descriptor audit shared by scan, CLI and MCP projections.

Findings are heuristics over observed descriptors, not exploitation proof.
Resource bodies, rendered prompts and authorization bypass are not assessed.
"""

from __future__ import annotations

import json
from copy import copy
from dataclasses import asdict
from typing import Any, cast

from agent_bom.core.severity import severity_at_or_above
from agent_bom.discovery.identity import server_identity_key
from agent_bom.enforcement import (
    EnforcementFinding,
    EnforcementReport,
    check_over_permission,
    expected_mcp_capabilities,
    scan_description_surfaces,
)
from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection
from agent_bom.mcp_tool_rules import evaluate_tool
from agent_bom.models import Agent, AIBOMReport, MCPServer
from agent_bom.risk_analyzer import ToolCapability
from agent_bom.security import sanitize_sensitive_payload


def _surface_coverage(
    configured: MCPServer,
    observed: MCPServer,
    result: ServerIntrospection | None,
    introspection_report: IntrospectionReport | None,
    agent: Agent,
    expected_capabilities: list[str] | None,
) -> dict[str, Any]:
    coverage: dict[str, Any] = {
        "server_name": configured.name,
        "server_identity": server_identity_key(configured),
        "server_canonical_id": configured.canonical_id,
        "agent_name": agent.name,
    }
    for kind in ("tools", "resources", "prompts"):
        static_items = list(getattr(configured, kind))
        runtime_items = list(getattr(result, "runtime_" + kind)) if result else []
        # Retain changed live descriptions as well as config evidence.
        items = list(static_items)
        for item in runtime_items:
            if item not in items:
                items.append(item)
        setattr(observed, kind, [copy(item) for item in items])
        status = "configuration_only"
        reason = "Only discovered configuration descriptors were inspected. Live listing was not collected."
        if result:
            status = result.surface_status.get(kind, "inspected" if runtime_items else "unknown")
            if not result.success and status == "unknown":
                status = "failed"
            reason = "Live descriptors were inspected; bodies and tool execution were not tested."
            if status != "inspected":
                reason = "Live listing is incomplete or unavailable; any retained descriptors were still inspected."
        elif configured.security_blocked:
            status, reason = "skipped", "Live connection blocked by security policy; only retained descriptors were inspected."
        elif introspection_report is not None:
            status, reason = "skipped", "No live result for this server identity; check transport eligibility and execution opt-in."
        coverage[kind] = {"discovered": len(items), "inspected": len(items), "status": status, "reason": reason}
    coverage["resource_content"] = {
        "status": "not_inspected",
        "reason": "General resource-body injection inspection was not performed.",
    }
    coverage["rendered_prompts"] = {"status": "not_inspected", "reason": "Audit does not render prompts."}
    coverage["authorization_bypass"] = {"status": "not_assessed", "reason": "Authentication checks inspect configuration only."}
    expected = expected_mcp_capabilities(agent.agent_type.value, expected_capabilities)
    coverage["permission_scope"] = {
        "status": "inspected" if expected is not None and observed.tools else "not_assessed",
        "basis": "operator_profile" if expected_capabilities is not None else "agent_type_heuristic",
        "expected_capabilities": sorted(c.value for c in expected) if expected is not None else None,
        "reason": "Capabilities are inferred from descriptors, not verified operating-system permissions."
        if expected is not None and observed.tools
        else "Missing tool descriptors or expected capability profile.",
    }
    return coverage


def _unique_findings(findings: list[EnforcementFinding]) -> list[EnforcementFinding]:
    """Merge repeated issues while retaining every affected agent."""
    unique: dict[str, EnforcementFinding] = {}
    for finding in findings:
        agent_name = finding.evidence.pop("agent_name", "")
        key = json.dumps(asdict(finding), sort_keys=True)
        if key not in unique:
            unique[key] = finding
            finding.evidence["affected_agents"] = []
        agents = unique[key].evidence["affected_agents"]
        if agent_name and agent_name not in agents:
            agents.append(agent_name)
    return list(unique.values())


def audit_mcp_agents(
    agents: list[Agent],
    *,
    introspection_report: IntrospectionReport | None = None,
    expected_capabilities: list[str] | None = None,
) -> EnforcementReport:
    """Inspect configuration and any collected live descriptors without writes.

    An explicit empty capability list means no capability is expected. Omitted
    profiles use the existing agent-type heuristic. Unknown agents remain
    unassessed for permission scope. Never join live observations by name alone.
    """
    if expected_capabilities is not None:
        expected_capabilities = sorted({ToolCapability(value).value for value in expected_capabilities})
    live = {r.server_identity: r for r in introspection_report.results if r.server_identity} if introspection_report else {}
    report = EnforcementReport()
    for agent in agents:
        for configured in agent.mcp_servers:
            if not configured.is_mcp_surface:
                continue
            identity = server_identity_key(configured)
            result = live.get(identity)
            observed = copy(configured)
            coverage = _surface_coverage(configured, observed, result, introspection_report, agent, expected_capabilities)
            observed.stamp_child_identities()
            findings = scan_description_surfaces([observed]).findings
            findings.extend(check_over_permission(observed, agent.agent_type.value, expected_capabilities=expected_capabilities))
            retained_rules = {
                (t.canonical_id, r.get("rule_id"), r.get("property_name")) for t in configured.tools for r in t.schema_rule_findings
            }
            for tool, rule in ((tool, rule) for tool in observed.tools for rule in evaluate_tool(tool)):
                if (tool.canonical_id, rule.rule_id, rule.property_name) in retained_rules:
                    continue  # Already promoted by the report's canonical tool-rule adapter.
                findings.append(
                    EnforcementFinding(
                        severity=rule.severity,
                        category="schema_risk",
                        server_name=observed.name,
                        tool_name=rule.tool_name,
                        surface_name=rule.tool_name,
                        reason=rule.title + ": " + rule.message,
                        recommendation="Constrain tool inputs and verify server-side validation before enabling the tool.",
                        evidence={
                            "basis": "schema_heuristic",
                            "asset_identifier": tool.canonical_id,
                            "rule_id": rule.rule_id,
                            "property_name": rule.property_name,
                            "cwe_ids": list(rule.cwe_ids),
                            "owasp_mcp_tags": list(rule.owasp_mcp_tags),
                        },
                    )
                )
            for finding in findings:
                finding.server_identity = identity
                finding.evidence = {**finding.evidence, "agent_name": agent.name, "server_canonical_id": configured.canonical_id}
            report.findings.extend(findings)
            report.coverage.append(cast(dict[str, Any], sanitize_sensitive_payload(coverage)))
            report.servers_checked += 1
            report.tools_checked += len(observed.tools)
    report.findings = _unique_findings(report.findings)
    report.passed = not any(severity_at_or_above(f.severity, "high") for f in report.findings)
    return report


def attach_passive_mcp_audit(report: AIBOMReport) -> None:
    """Attach one passive evaluation and auth evidence before graph/export work."""
    if report.enforcement_data is None:
        report.enforcement_data = audit_mcp_agents(report.agents).to_dict()
    existing = {finding.id for finding in report.findings}
    from agent_bom.discovery.agent_permission_posture import evaluate_agent_permission_posture

    for finding in [*evaluate_mcp_auth_posture(report.agents), *evaluate_agent_permission_posture(report.agents)]:
        if finding.id not in existing:
            report.findings.append(finding)
            existing.add(finding.id)
