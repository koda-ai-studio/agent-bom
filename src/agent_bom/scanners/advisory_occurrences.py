"""Every package occurrence a stored scan report carries, for advisory matching.

A report records packages in two places. Agents carry MCP servers (and the
server-shaped wrappers of filesystem, SBOM, repository and image scans) whose
``packages`` lists are the inventory. Container-image and SBOM-only package
occurrences that the correlation step recorded as their own assets (the
estate's ``pkg:<eco>:<name>@<version>:image:<digest>`` rows) live only in the
``blast_radius`` section, one row per advisory on the occurrence, with no agent
or server above them. "Am I affected?" must examine both, exactly as the
findings list shows both, so this walk yields each occurrence once.

This module stays free of the graph package: node ids are added by the caller.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

# Section names a stored report has used for its blast-radius rows, newest first.
BLAST_RADIUS_SECTIONS = ("blast_radius", "vulnerabilities")


@dataclass(frozen=True)
class ReportOccurrence:
    """One package on one asset: ``owners`` is ``(agent, server)`` for the agent tree, ``None`` for a standalone asset."""

    asset: dict[str, str]
    package: dict[str, Any]
    owners: tuple[dict, dict] | None


def iter_agent_tree_packages(report: dict[str, Any]) -> Iterator[ReportOccurrence]:
    for agent in report.get("agents") or []:
        if not isinstance(agent, dict):
            continue
        for server in agent.get("mcp_servers") or []:
            if not isinstance(server, dict):
                continue
            for package in server.get("packages") or []:
                if isinstance(package, dict) and package.get("name") and package.get("version"):
                    asset = {"agent": str(agent.get("name") or ""), "server": str(server.get("name") or "")}
                    yield ReportOccurrence(asset, package, (agent, server))


def _blast_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    for section in BLAST_RADIUS_SECTIONS:
        rows = report.get(section)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def unexamined_sections(report: dict[str, Any]) -> list[str]:
    """Sections the report carries in a shape this walk cannot read; the answer must say so."""
    return [section for section in BLAST_RADIUS_SECTIONS if section in report and not isinstance(report.get(section), list)]


def _is_standalone(row: dict[str, Any]) -> bool:
    """A blast-radius row whose package no agent or server carries: the asset is the package occurrence itself."""
    asset = row.get("asset")
    if not isinstance(asset, dict) or str(asset.get("asset_type") or "") == "mcp_server":
        return False
    return not (row.get("affected_servers") or row.get("affected_agents") or row.get("affected_agent_ids"))


def _standalone_key(row: dict[str, Any]) -> str:
    asset = row["asset"]
    return str(asset.get("identifier") or asset.get("stable_id") or "") or f"{row.get('package_stable_id') or ''}|{asset.get('name') or ''}"


def _purl(row: dict[str, Any]) -> str | None:
    asset = row["asset"]
    for candidate in (row.get("purl"), asset.get("location"), asset.get("identifier")):
        if isinstance(candidate, str) and candidate.startswith("pkg:") and "/" in candidate:
            return candidate
    return None


def _vulnerability(row: dict[str, Any]) -> dict[str, Any] | None:
    identifier = row.get("vulnerability_id") or row.get("cve_id")
    if not identifier:
        return None
    aliases = [str(alias) for alias in (row.get("advisory_aliases") or []) if alias]
    return {
        "id": str(identifier),
        "aliases": aliases,
        "severity": row.get("severity"),
        "severity_source": row.get("severity_source"),
        "cvss_score": row.get("cvss_score"),
        "fixed_version": row.get("fixed_version"),
        "summary": row.get("summary") or row.get("description") or "",
    }


def iter_standalone_packages(report: dict[str, Any]) -> Iterator[ReportOccurrence]:
    """Image/SBOM-only occurrences recorded as their own assets, one per asset with every advisory on it."""
    grouped: dict[str, ReportOccurrence] = {}
    for row in _blast_rows(report):
        if not _is_standalone(row):
            continue
        name = row.get("package_name") or str(row.get("package") or "").rsplit("@", 1)[0]
        version = row.get("package_version") or (str(row["package"]).rsplit("@", 1)[1] if "@" in str(row.get("package") or "") else "")
        if not name or not version:
            continue
        key = _standalone_key(row)
        occurrence = grouped.get(key)
        if occurrence is None:
            asset_info = row["asset"]
            node_id = str(asset_info.get("identifier") or "")
            asset = {"agent": "", "server": "", "asset_type": str(asset_info.get("asset_type") or "package"), "node_id": node_id}
            package: dict[str, Any] = {
                "name": str(name),
                "version": str(version),
                "ecosystem": str(row.get("ecosystem") or ""),
                "purl": _purl(row),
                "stable_id": row.get("package_stable_id") or asset_info.get("stable_id"),
                "asset_name": asset_info.get("name"),
                "vulnerabilities": [],
            }
            occurrence = grouped[key] = ReportOccurrence(asset, package, None)
        vulnerability = _vulnerability(row)
        if vulnerability and vulnerability["id"] not in {v["id"] for v in occurrence.package["vulnerabilities"]}:
            occurrence.package["vulnerabilities"].append(vulnerability)
    yield from grouped.values()


def iter_report_occurrences(report: dict[str, Any]) -> Iterator[ReportOccurrence]:
    """Every package occurrence of one stored report: the agent tree first, then standalone assets."""
    yield from iter_agent_tree_packages(report)
    yield from iter_standalone_packages(report)


def asset_key(scan_id: str, asset: dict[str, str]) -> tuple[str, str, str, str]:
    """The examined-asset identity: a server under an agent, or a standalone asset's node id."""
    return (scan_id, asset.get("agent", ""), asset.get("server", ""), asset.get("node_id", ""))
