"""Portable views of frozen technique associations for human and machine reports."""

from __future__ import annotations

import json
from html import escape
from typing import Any

from agent_bom.evidence.finding_response_fields import safe_atlas_mapping_evidence
from agent_bom.output.finding_views import sanitize_output_text


def _source_rows(findings: list) -> list[tuple[str, str, dict]]:
    rows = []
    for finding in findings:
        for technique, receipt in safe_atlas_mapping_evidence(finding.evidence.get("atlas_mapping_evidence")).items():
            chain = " → ".join([", ".join(receipt["cwe_ids"]), receipt["attack_reference"], technique])
            rows.append((sanitize_output_text(finding.id), chain, receipt))
    return rows


def html_atlas_sources(findings: list) -> str:
    rows = []
    for identifier, chain, receipt in _source_rows(findings):
        rows.append(
            f"<li>{escape(identifier)}: {escape(chain)}"
            f"<br>ATLAS SHA-256: <code>{receipt['atlas_catalog_sha256']}</code>"
            f"<br>ATT&amp;CK bridge SHA-256: <code>{receipt['attack_catalog_sha256']}</code></li>"
        )
    return (
        "<details><summary>ATLAS mapping sources — execution not established</summary>"
        '<ul style="overflow-wrap:anywhere">' + "".join(rows) + "</ul></details>"
        if rows
        else ""
    )


def markdown_atlas_sources(findings: list) -> list[str]:
    lines = []
    for identifier, chain, receipt in _source_rows(findings):
        lines.extend(
            [
                f"- {identifier.replace('|', chr(92) + '|')}: {chain}",
                f"  - ATLAS SHA-256: `{receipt['atlas_catalog_sha256']}`",
                f"  - ATT&CK bridge SHA-256: `{receipt['attack_catalog_sha256']}`",
            ]
        )
    return ["## ATLAS mapping sources", "", "Weakness associations; execution not established.", "", *lines, ""] if lines else []


def scoped_vulnerability_properties(pkg_ref: str, workflow: dict[str, str], atlas_receipts: list[dict] | None) -> list[dict[str, str]]:
    properties = []
    if workflow:
        properties.append(
            {"name": "agent-bom:workflow", "value": json.dumps({"affects_ref": pkg_ref, **workflow}, sort_keys=True, separators=(",", ":"))}
        )
    if atlas_receipts:
        properties.append(
            {
                "name": "agent-bom:atlas-mapping-evidence",
                "value": json.dumps({"affects_ref": pkg_ref, "receipts": atlas_receipts}, sort_keys=True, separators=(",", ":")),
            }
        )
    return properties


def copy_atlas_graph_receipts(graph: Any, unified: Any) -> None:
    """Retain the legacy dependency shape while joining exact canonical endpoints."""
    canonical_edges = {(edge.source, edge.target): edge for edge in unified.edges if edge.relationship.value == "vulnerable_to"}
    for edge in graph.edges:
        if edge.kind != "affects":
            continue
        source = graph._nodes[edge.source].attributes.get("canonical_node_id")
        target = graph._nodes[edge.target].attributes.get("canonical_node_id")
        canonical = canonical_edges.get((source, target))
        if canonical is not None and canonical.evidence.get("atlas_mapping_receipts"):
            edge.evidence["atlas_mapping_receipts"] = canonical.evidence["atlas_mapping_receipts"]
