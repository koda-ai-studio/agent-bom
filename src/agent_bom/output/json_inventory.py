"""Inventory and entity snapshots for JSON reports."""

from __future__ import annotations

from typing import Any

from agent_bom.asset_provenance import (
    agent_discovery_provenance,
    package_discovery_provenance,
    package_version_provenance,
    sanitize_discovery_provenance,
)
from agent_bom.canonical_ids import agent_identity_export, canonical_id
from agent_bom.evidence.occurrence_ids import server_occurrence_id
from agent_bom.evidence.scan_run import effective_scan_run, vulnerability_scan_skipped
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.models import AIBOMReport, MCPServer
from agent_bom.output.json_sections import _package_occurrence_to_dict
from agent_bom.security import (
    sanitize_command_args,
    sanitize_path_label,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)

INVENTORY_SNAPSHOT_SCHEMA_VERSION = "1"


def _build_ai_bom_entities_snapshot(report: AIBOMReport, *, vulnerabilities_scanned: bool = True) -> dict:
    """Build a deterministic inventory snapshot for diffing and BOM operations.

    ``vulnerability_count`` is null with ``vulnerability_status: "not_scanned"``
    when no vulnerability lookup ran, so an unscanned package never reads as clean.
    """
    scanned = vulnerabilities_scanned and not vulnerability_scan_skipped(effective_scan_run(report))
    agents: list[dict] = []
    servers: dict[str, dict] = {}
    tools: dict[str, dict] = {}
    resources: dict[str, dict] = {}
    prompts: dict[str, dict] = {}
    packages: dict[str, dict] = {}
    relationships: list[dict] = []

    for agent in report.agents:
        server_ids: list[str] = []
        agent_provenance = agent_discovery_provenance(agent)
        agents.append(
            {
                **agent_identity_export(agent),
                "name": agent.name,
                "agent_type": agent.agent_type.value,
                "type": agent.agent_type.value,
                "status": agent.status.value,
                "discovered_at": agent.discovered_at,
                "last_seen": agent.last_seen,
                "config_path": sanitize_path_label(agent.config_path) if agent.config_path else "",
                "discovery_provenance": agent_provenance,
                "server_ids": server_ids,
            }
        )

        for server in agent.mcp_servers:
            server_id = server_occurrence_id(server, agent)
            server_ids.append(server_id)
            if server_id not in servers:
                servers[server_id] = {
                    "id": server_id,
                    "canonical_id": server.canonical_id,
                    "name": server.name,
                    "surface": server.surface.value,
                    "fingerprint": server.fingerprint,
                    "auth_mode": server.auth_mode,
                    "transport": server.transport.value,
                    "command": sanitize_text(server.command),
                    "url": sanitize_url(server.url),
                    "tool_ids": {},
                    "resource_ids": {},
                    "prompt_ids": {},
                    "package_ids": {},
                    "discovery_provenance": sanitize_discovery_provenance(
                        getattr(server, "discovery_provenance", None),
                        defaults=agent_provenance,
                    ),
                }
            relationships.append({"from": agent.stable_id, "to": server_id, "type": "uses"})

            _append_mcp_entities(server, server_id, servers, tools, resources, prompts, relationships)

            _append_package_entities(server, server_id, servers, packages, relationships, agent_provenance, scanned=scanned)

    for server_row in servers.values():
        server_row.update({key: list(server_row[key]) for key in ("tool_ids", "resource_ids", "prompt_ids", "package_ids")})
    return _snapshot_payload(agents, relationships, servers=servers, tools=tools, resources=resources, prompts=prompts, packages=packages)


def _append_package_entities(
    server: MCPServer,
    server_id: str,
    servers: dict[str, dict],
    packages: dict[str, dict],
    relationships: list[dict],
    agent_provenance: dict | None,
    *,
    scanned: bool = True,
) -> None:
    """Keep package identity and per-server dependency edges in insertion order."""
    for pkg in server.packages:
        if pkg.stable_id not in packages:
            packages[pkg.stable_id] = {
                "id": pkg.stable_id,
                "canonical_id": pkg.canonical_id,
                "name": pkg.name,
                "version": pkg.version,
                "ecosystem": pkg.ecosystem,
                "purl": pkg.purl,
                "source_package": pkg.source_package,
                "distro_name": pkg.distro_name,
                "distro_version": pkg.distro_version,
                "floating_reference": pkg.floating_reference,
                "floating_reference_reason": pkg.floating_reference_reason,
                "is_malicious": pkg.is_malicious,
                "malicious_reason": pkg.malicious_reason,
                "version_provenance": package_version_provenance(pkg, inherited=agent_provenance),
                "discovery_provenance": package_discovery_provenance(pkg, inherited=agent_provenance),
                "occurrence_count": len(pkg.occurrences),
                "occurrences": [_package_occurrence_to_dict(occ) for occ in pkg.occurrences],
                "vulnerability_count": len(pkg.vulnerabilities) if scanned else None,
                "vulnerability_status": "scanned" if scanned else "not_scanned",
            }
        servers[server_id]["package_ids"][pkg.stable_id] = None
        relationships.append({"from": server_id, "to": pkg.stable_id, "type": "depends_on"})


def _append_mcp_entities(
    server: MCPServer,
    server_id: str,
    servers: dict[str, dict],
    tools: dict[str, dict],
    resources: dict[str, dict],
    prompts: dict[str, dict],
    relationships: list[dict],
) -> None:
    """Project advertised capabilities without collapsing server occurrences."""
    for tool in server.tools:
        tool_id = canonical_id("tool_occurrence", server_id, tool.stable_id)
        if tool_id not in tools:
            tools[tool_id] = {
                "id": tool_id,
                "canonical_id": tool.canonical_id,
                "name": tool.name,
                "fingerprint": tool.fingerprint,
                "description": tool.description,
                "discovery_source": tool.discovery_source,
                "discovery_confidence": tool.discovery_confidence,
                "schema_findings": tool.schema_findings,
                "schema_rule_findings": tool.schema_rule_findings,
                "risk_score": tool.risk_score,
            }
        servers[server_id]["tool_ids"][tool_id] = None
        relationships.append({"from": server_id, "to": tool_id, "type": "exposes_tool"})

    for resource in server.resources:
        resource_id = canonical_id("resource_occurrence", server_id, resource.stable_id)
        if resource_id not in resources:
            resources[resource_id] = {
                "id": resource_id,
                "canonical_id": resource.canonical_id,
                "uri": resource.uri,
                "name": resource.name,
                "fingerprint": resource.fingerprint,
                "mime_type": resource.mime_type,
                "content_findings": resource.content_findings,
                "risk_score": resource.risk_score,
            }
        servers[server_id]["resource_ids"][resource_id] = None
        relationships.append({"from": server_id, "to": resource_id, "type": "exposes_resource"})

    for prompt in server.prompts:
        prompt_id = canonical_id("prompt_occurrence", server_id, prompt.stable_id)
        if prompt_id not in prompts:
            prompts[prompt_id] = {
                "id": prompt_id,
                "canonical_id": prompt.canonical_id,
                "name": prompt.name,
                "fingerprint": prompt.fingerprint,
                "description": prompt.description,
                "arguments": prompt.arguments,
                "content_findings": prompt.content_findings,
                "risk_score": prompt.risk_score,
            }
        servers[server_id]["prompt_ids"][prompt_id] = None
        relationships.append({"from": server_id, "to": prompt_id, "type": "exposes_prompt"})


def _snapshot_payload(agents: list[dict], relationships: list[dict], **entities: dict[str, dict]) -> dict:
    return {
        "summary": {"agents": len(agents), **{name: len(rows) for name, rows in entities.items()}, "relationships": len(relationships)},
        "agents": agents,
        **{name: sorted(rows.values(), key=lambda row: row["id"]) for name, rows in entities.items()},
        "relationships": relationships,
    }


_INVENTORY_SCHEMA_AGENT_TYPES = {"claude-desktop", "claude-code", "cursor", "windsurf", "cline", "custom"}
_INVENTORY_SCHEMA_ECOSYSTEMS = {"npm", "pypi", "go", "cargo", "maven", "nuget", "hex", "pub", "unknown"}
_INVENTORY_SCHEMA_TRANSPORTS = {"stdio", "sse", "streamable-http"}
_SECURITY_INTELLIGENCE_SCHEMA_FIELDS = {
    "entry_id",
    "title",
    "severity",
    "confidence",
    "default_recommendation",
    "source_type",
    "source",
    "match_type",
    "matched_value",
    "ecosystem",
    "package",
    "affected_versions",
    "first_seen",
    "last_verified",
    "references",
    "remediation_actions",
}
_DISCOVERY_PROVENANCE_SCHEMA_FIELDS = {
    "source_type",
    "observed_via",
    "source",
    "collector",
    "provider",
    "service",
    "resource_type",
    "resource_id",
    "resource_name",
    "location",
    "confidence",
    "resolved_from_registry",
    "version_source",
    "version_provenance",
}
_VERSION_PROVENANCE_SCHEMA_FIELDS = {
    "declared_name",
    "declared_version",
    "resolved_version",
    "version_source",
    "confidence",
    "observed_at",
    "version_resolved_at",
    "resolved_from_registry",
    "floating_reference",
    "floating_reference_reason",
    "evidence",
    "version_conflicts",
}


def _drop_empty(value: dict[str, object | None]) -> dict[str, object]:
    """Drop optional empty values so inventory output validates with strict schema."""
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _schema_agent_type(value: str) -> str:
    return value if value in _INVENTORY_SCHEMA_AGENT_TYPES else "custom"


def _schema_ecosystem(value: str | None) -> str:
    normalized = (value or "unknown").lower()
    return normalized if normalized in _INVENTORY_SCHEMA_ECOSYSTEMS else "unknown"


def _schema_transport(value: str) -> str | None:
    return value if value in _INVENTORY_SCHEMA_TRANSPORTS else None


def _schema_security_intelligence(entry: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_security_intelligence_entry(entry)
    return {key: value for key, value in sanitized.items() if key in _SECURITY_INTELLIGENCE_SCHEMA_FIELDS}


def _schema_version_provenance(value: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    filtered = {key: item for key, item in value.items() if key in _VERSION_PROVENANCE_SCHEMA_FIELDS}
    return _drop_empty(filtered)


def _schema_discovery_provenance(value: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    filtered: dict[str, object | None] = {key: item for key, item in value.items() if key in _DISCOVERY_PROVENANCE_SCHEMA_FIELDS}
    version_provenance = value.get("version_provenance")
    filtered["version_provenance"] = _schema_version_provenance(version_provenance if isinstance(version_provenance, dict) else None)
    return _drop_empty(filtered)


def _schema_package(pkg, *, inherited_provenance: dict | None = None) -> dict[str, object]:
    provenance = _schema_discovery_provenance(package_discovery_provenance(pkg, inherited=inherited_provenance))
    package = _drop_empty(
        {
            "name": sanitize_text(pkg.name),
            "version": sanitize_text(pkg.version or "unknown"),
            "ecosystem": _schema_ecosystem(pkg.ecosystem),
            "purl": sanitize_text(pkg.purl) if pkg.purl else None,
            "discovery_provenance": provenance,
        }
    )
    return package


def _schema_tool(tool) -> dict[str, object]:
    return _drop_empty(
        {
            "name": sanitize_text(tool.name),
            "description": sanitize_text(tool.description),
            "input_schema": sanitize_sensitive_payload(tool.input_schema or {}),
        }
    )


def _schema_server(server, *, inherited_provenance: dict | None = None) -> dict[str, object]:
    raw_intel = getattr(server, "security_intelligence", []) or []
    security_intelligence = [
        item
        for item in (_schema_security_intelligence(entry) for entry in raw_intel if isinstance(entry, dict))
        if item.get("entry_id") and item.get("title") and item.get("confidence") and item.get("default_recommendation")
    ]
    server_payload = _drop_empty(
        {
            "name": sanitize_text(server.name),
            "command": sanitize_text(server.command),
            "args": sanitize_command_args(server.args),
            "transport": _schema_transport(server.transport.value),
            "url": sanitize_url(server.url) if server.url else None,
            "mcp_version": sanitize_text(server.mcp_version) if server.mcp_version else None,
            "working_dir": sanitize_path_label(server.working_dir) if server.working_dir else None,
            "tools": [_schema_tool(tool) for tool in server.tools],
            "packages": [_schema_package(pkg, inherited_provenance=inherited_provenance) for pkg in server.packages],
            "config_path": sanitize_path_label(server.config_path) if server.config_path else None,
            "security_blocked": server.security_blocked if server.security_blocked else None,
            "security_warnings": sanitize_security_warnings(server.security_warnings),
            "security_intelligence": security_intelligence,
            "discovery_provenance": _schema_discovery_provenance(
                sanitize_discovery_provenance(
                    getattr(server, "discovery_provenance", None),
                    defaults=inherited_provenance,
                )
            ),
        }
    )
    return server_payload


def _build_inventory_snapshot(report: AIBOMReport) -> dict:
    """Build a strict inventory-schema payload suitable for --inventory reuse."""
    agents: list[dict[str, object]] = []
    packages: list[dict[str, object]] = []
    for agent in report.agents:
        agent_provenance = _schema_discovery_provenance(agent_discovery_provenance(agent))
        agents.append(
            _drop_empty(
                {
                    "name": sanitize_text(agent.name),
                    "agent_type": _schema_agent_type(agent.agent_type.value),
                    "version": sanitize_text(agent.version) if agent.version else None,
                    "config_path": sanitize_path_label(agent.config_path) if agent.config_path else None,
                    "source": sanitize_text(agent.source) if agent.source else None,
                    "metadata": sanitize_sensitive_payload(agent.metadata) if agent.metadata else None,
                    "discovered_at": agent.discovered_at,
                    "last_seen": agent.last_seen,
                    "mcp_servers": [_schema_server(server, inherited_provenance=agent_provenance) for server in agent.mcp_servers],
                    "discovery_provenance": agent_provenance,
                }
            )
        )
        for server in agent.mcp_servers:
            packages.extend(_schema_package(pkg, inherited_provenance=agent_provenance) for pkg in server.packages)

    return {
        "schema_version": INVENTORY_SNAPSHOT_SCHEMA_VERSION,
        "generated_at": report.generated_at.isoformat(),
        "packages": packages,
        "agents": agents,
    }


def inventory_package_row(pkg: Any) -> dict[str, Any]:
    """Compact MCP inventory package row; `version` stays for compatibility, pinning is explicit."""
    provenance = package_version_provenance(pkg)
    return {
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "pinned": bool(provenance.get("pinned")),
        "pinned_version": provenance.get("pinned_version"),
        "observed_version": provenance.get("resolved_version"),
        "version_source": provenance.get("version_source"),
    }
