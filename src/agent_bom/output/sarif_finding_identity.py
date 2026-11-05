"""Where a unified SARIF finding lives and what identifies it across checkouts."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from agent_bom.finding import Finding
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif_common import _ecosystem_from_purl, _to_relative_path, identity_uri, scan_root_path
from agent_bom.output.source_locations import _relative_uri, evidence_relative_path
from agent_bom.scan_delta import canonical_identity_text


def _report_root_labels(report: AIBOMReport) -> set[str]:
    labels = {agent.name.removeprefix("project:") for agent in report.agents if agent.name.startswith("project:")}
    root = scan_root_path(report)
    return {*labels, Path(root).name} - {""} if root else labels


def unified_identity(finding: Finding, rule_id: str, file_path: str | None, report: AIBOMReport) -> str:
    """Stable result identity: the same rule, file and text on any checkout, at any line.

    ``finding.id`` and ``asset.stable_id`` hash the absolute path or the agent name for
    several finding kinds, so they cannot identify a finding across checkouts. Repeats in
    one file are told apart in :func:`number_repeated_identities`.
    """
    roots = _report_root_labels(report)
    return ":".join(
        [
            rule_id,
            identity_uri(file_path, report) if file_path else finding.asset.asset_type,
            canonical_identity_text(finding.title or "", roots),
            canonical_identity_text(finding.description or "", roots),
        ]
    )


def _is_path_like(value: str | None) -> bool:
    """False for a redacted label, a launch command or a URL, none of which name a file."""
    return bool(value) and not str(value).startswith("<") and "://" not in str(value) and not any(ch.isspace() for ch in str(value))


def _agent_config_uri(finding: Finding, report: AIBOMReport) -> str | None:
    """The MCP config behind an agent-scoped finding: it declares what the agent can reach."""
    if finding.asset.asset_type != "agent":
        return None
    agent = next((agent for agent in report.agents if agent.name == finding.asset.name), None)
    for server in agent.mcp_servers if agent else []:
        if _is_path_like(server.config_path) and Path(str(server.config_path)).is_file():
            uri = _relative_uri(str(server.config_path), scan_root_path(report))
            if uri:
                return uri
    return None


def finding_file_uri(finding: Finding, report: AIBOMReport) -> str | None:
    """The source file that produced a finding, or None when none is known."""
    location, identifier = finding.asset.location, finding.asset.identifier
    if _is_path_like(location):
        return _to_relative_path(str(location), _ecosystem_from_purl(identifier))
    uri = evidence_relative_path(finding.evidence)
    if uri is None and _is_path_like(identifier) and Path(str(identifier)).is_file():
        uri = _relative_uri(str(identifier), scan_root_path(report))
    return uri or _agent_config_uri(finding, report)


def number_repeated_identities(results: list[dict[str, Any]]) -> None:
    """Keep one identity per result when a file repeats the same finding on several lines."""
    seen: Counter[str] = Counter()
    for result in results:
        fingerprints = result.get("fingerprints") or {}
        value = fingerprints.get("agent-bom/v1")
        if value:
            seen[value] += 1
            if seen[value] > 1:
                fingerprints["agent-bom/v1"] = hashlib.sha256(f"{value}#{seen[value]}".encode()).hexdigest()
