"""A blast-radius row without an ecosystem lands on the inventoried package it names.

Rows imported from other producers can omit ``ecosystem``. Minting
``pkg::name@version`` for them put the same package in the graph twice: the
inventoried node under its server, and an ecosystem-less twin holding the CVE
as a separate top-level root. The rule is deterministic: adopt the ecosystem
only when exactly one inventoried package matches the name and version within
the row's affected servers (or the estate, when the row names none). Anything
ambiguous keeps the reported-package node rather than guessing.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph import RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report


def _server(name: str, packages: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": name, "command": "npx", "args": [name], "packages": packages, "tools": []}


def _report(blast: dict[str, Any], *servers: dict[str, Any]) -> dict[str, Any]:
    return {
        "agents": [{"name": "agent-a", "type": "custom", "source": "local", "mcp_servers": list(servers)}],
        "blast_radius": [blast],
    }


def _vuln_holders(graph: Any, vuln: str) -> set[str]:
    return {e.source for e in graph.edges if e.target == f"vuln:{vuln}" and e.relationship == RelationshipType.VULNERABLE_TO}


def test_row_without_ecosystem_attaches_to_the_unique_inventoried_package() -> None:
    blast = {
        "vulnerability_id": "CVE-2026-0001",
        "severity": "high",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "affected_servers": ["srv-a"],
        "affected_agents": ["agent-a"],
    }
    graph = build_unified_graph_from_report(
        _report(blast, _server("srv-a", [{"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"}]))
    )
    assert "pkg::left-pad@1.0.0" not in graph.nodes
    assert "pkg:npm:left-pad@1.0.0" in _vuln_holders(graph, "CVE-2026-0001")
    edge = next(e for e in graph.edges if e.source == "pkg:npm:left-pad@1.0.0" and e.target == "vuln:CVE-2026-0001")
    assert edge.evidence.get("ecosystem_basis") == "inventory_package_match"


def test_ambiguous_name_keeps_the_reported_package() -> None:
    blast = {"vulnerability_id": "CVE-2026-0002", "severity": "low", "package_name": "requests", "package_version": "2.0.0"}
    graph = build_unified_graph_from_report(
        _report(
            blast,
            _server("srv-a", [{"name": "requests", "version": "2.0.0", "ecosystem": "pypi"}]),
            _server("srv-b", [{"name": "requests", "version": "2.0.0", "ecosystem": "npm"}]),
        )
    )
    assert "pkg::requests@2.0.0" in _vuln_holders(graph, "CVE-2026-0002")
    assert "pkg:pypi:requests@2.0.0" not in _vuln_holders(graph, "CVE-2026-0002")


def test_affected_server_narrows_an_ambiguous_name() -> None:
    blast = {
        "vulnerability_id": "CVE-2026-0003",
        "severity": "medium",
        "package_name": "requests",
        "package_version": "2.0.0",
        "affected_servers": ["srv-b"],
    }
    graph = build_unified_graph_from_report(
        _report(
            blast,
            _server("srv-a", [{"name": "requests", "version": "2.0.0", "ecosystem": "pypi"}]),
            _server("srv-b", [{"name": "requests", "version": "2.0.0", "ecosystem": "npm"}]),
        )
    )
    assert "pkg:npm:requests@2.0.0" in _vuln_holders(graph, "CVE-2026-0003")
    assert "pkg::requests@2.0.0" not in graph.nodes


def test_version_mismatch_is_not_merged() -> None:
    blast = {"vulnerability_id": "CVE-2026-0004", "severity": "low", "package_name": "left-pad", "package_version": "9.9.9"}
    graph = build_unified_graph_from_report(
        _report(blast, _server("srv-a", [{"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"}]))
    )
    assert "pkg::left-pad@9.9.9" in _vuln_holders(graph, "CVE-2026-0004")
