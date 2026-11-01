"""Structural identifiers (exposure path ids, purls, server refs, receipts) survive redaction; secrets inside them do not."""

from __future__ import annotations

import json

import pytest

from agent_bom import output
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.security import sanitize_sensitive_payload

REDACTED = "***REDACTED***"
_SCOPED = "@modelcontextprotocol/server-filesystem"
_STRUCTURAL_SUFFIXES = ("_id", "_ids", "_purl", "_ref", "_refs", "purl")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("exposure_path_id", f"blast:cve-2025-53109:npm:{_SCOPED}:0.6.2"),
        ("package_purl", "pkg:npm/%40modelcontextprotocol/server-filesystem@0.6.2"),
        ("server_ref", "server:cfg-951c3b9629c8:project%3Amcpfix:8b935889-c3f0-5d30-8a1d-abf54e832b25"),
        ("server_ref", "server:cfg-951c3b9629c8:project%3Amcpfix:files"),
        ("mcp_server_ref", "server:cfg-951c3b9629c8:project%3Amcpfix:files"),
        ("bom_ref", "pkg:npm/%40modelcontextprotocol/server-filesystem@0.6.2"),
    ],
)
def test_structural_identifier_values_survive(key, value):
    assert sanitize_sensitive_payload({key: value}) == {key: value}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("release", "pypi-note:/Users/me/src/quickstarts/requirements.txt"),
        ("release", "npm:/home/ci/work/managed-agents/server/package.json"),
    ],
)
def test_coverage_receipts_keep_their_prefix_and_basename(key, value):
    redacted = sanitize_sensitive_payload({key: value})[key]
    prefix, _, path = value.partition(":")
    assert redacted.startswith(f"{prefix}:<path:")
    assert redacted.endswith(f"{path.rsplit('/', 1)[-1]}>")
    assert "/Users/" not in redacted and "/home/" not in redacted


@pytest.mark.parametrize("key", ["exposure_path_id", "package_purl", "server_ref", "bom_ref"])
def test_secret_patterns_still_redact_inside_identifier_keys(key):
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    assert token not in json.dumps(sanitize_sensitive_payload({key: f"blast:cve-2025-1:npm:{token}:1.0"}))
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    assert aws not in json.dumps(sanitize_sensitive_payload({key: f"pkg:npm/{aws}@1.0"}))
    opaque = "blast:" + "zXq9Kp2vLm8Rt4Yw7Nb3Hd6Fj1Gs5Ac0Ve"
    assert sanitize_sensitive_payload({key: opaque}) == {key: REDACTED}


def _report() -> AIBOMReport:
    vulnerability = Vulnerability(id="CVE-2025-53109", severity=Severity.HIGH, summary="Path traversal")
    package = Package(
        name=_SCOPED,
        version="0.6.2",
        ecosystem="npm",
        purl="pkg:npm/%40modelcontextprotocol/server-filesystem@0.6.2",
        vulnerabilities=[vulnerability],
    )
    server = MCPServer(name="files", command="npx", args=["-y", f"{_SCOPED}@0.6.2", "/Users/me/projects"], packages=[package])
    agent = Agent(name="project:mcpfix", agent_type=AgentType.CUSTOM, config_path="/Users/me/projects/.mcp.json", mcp_servers=[server])
    blast = BlastRadius(
        package=package,
        vulnerability=vulnerability,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    return AIBOMReport(agents=[agent], blast_radii=[blast])


def _redacted_structural_keys(value: object, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if child == REDACTED and str(key).lower().endswith(_STRUCTURAL_SUFFIXES):
                hits.append(f"{path}.{key}")
            hits.extend(_redacted_structural_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(_redacted_structural_keys(child, f"{path}[{index}]"))
    return hits


def test_redacted_json_report_keeps_every_structural_identifier_for_scoped_npm_packages():
    document = output.to_redacted_json(_report())
    assert _redacted_structural_keys(document) == []
    purls = [finding["evidence"].get("package_purl") for finding in document["findings"] if finding["evidence"].get("package_purl")]
    assert purls and all(purl.startswith("pkg:npm/") and purl.endswith("server-filesystem@0.6.2") for purl in purls)
    path_ids = [row["exposure_path_id"] for row in document["blast_radius"]]
    assert path_ids and all(pid.startswith("blast:cve-2025-53109:npm:") and "server-filesystem" in pid for pid in path_ids)
    server_refs = [link["server_ref"] for finding in document["findings"] for link in finding["evidence"].get("agent_server_links", [])]
    assert server_refs and all(ref.startswith("server:") for ref in server_refs)


@pytest.mark.parametrize("format_name", ["to_sarif", "to_cyclonedx", "to_spdx"])
def test_other_exports_keep_scoped_npm_identity(format_name):
    rendered = getattr(output, format_name)(_report())
    text = json.dumps(rendered) if isinstance(rendered, dict) else rendered
    assert "server-filesystem" in text
    assert REDACTED not in text
