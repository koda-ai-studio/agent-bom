"""Multi-source correlation engine — deduplication, provenance, SBOM enrichment.

When agent-bom collects data from multiple sources (local discovery, cloud
providers, Docker images, SBOMs, Snyk, etc.), the same package can appear
from different sources with different version strings or ecosystem labels.

This module:
1. Collapses exact duplicate package entries within a single server, and never
   removes a package occurrence from a server or collapses distinct versions
2. Fills an "unknown"/"latest" version only when all sources agree on one
3. Shares vulnerability lists between identical (name, ecosystem, version)
   occurrences (deduplicated by vuln ID)
4. Reverse-looks up SBOM packages to find which agents use them
5. Tracks source provenance for the "full picture" view
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field

from agent_bom.models import Agent, MCPServer, Package

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Result of multi-source correlation."""

    deduplicated_packages: int = 0
    cross_source_matches: int = 0
    enriched_from_sbom: int = 0
    source_summary: dict[str, int] = field(default_factory=dict)


_UNKNOWN_VERSIONS = frozenset({"unknown", "latest", ""})


def _merge_vulns(pkg: Package, other: Package) -> int:
    """Merge vulnerabilities from other into pkg, avoiding duplicates. Returns count added."""
    existing_ids = {v.id.upper() for v in pkg.vulnerabilities}
    added = 0
    for v in other.vulnerabilities:
        if v.id.upper() not in existing_ids:
            pkg.vulnerabilities.append(copy.copy(v))
            existing_ids.add(v.id.upper())
            added += 1
    return added


def _unknown(version: str) -> bool:
    return (version or "").strip().lower() in _UNKNOWN_VERSIONS


def _dedupe_server_packages(server: MCPServer) -> int:
    """Collapse duplicate (name, ecosystem, version) entries within one server."""
    kept: dict[tuple[str, str, str], Package] = {}
    unique: list[Package] = []
    removed = 0
    for pkg in server.packages:
        key = (pkg.name.lower(), pkg.ecosystem.lower(), (pkg.version or "").strip())
        primary = kept.get(key)
        if primary is None:
            kept[key] = pkg
            unique.append(pkg)
            continue
        _merge_vulns(primary, pkg)
        if not primary.purl and pkg.purl:
            primary.purl = pkg.purl
        removed += 1
    if removed:
        server.packages = unique
    return removed


def _cross_reference(packages: list[Package]) -> None:
    """Add evidence across occurrences of one (name, ecosystem) without removing any."""
    specific = {p.version.strip() for p in packages if not _unknown(p.version)}
    if len(specific) == 1:
        only = next(iter(specific))
        for pkg in packages:
            if _unknown(pkg.version):
                pkg.version = only
    by_version: dict[str, list[Package]] = {}
    for pkg in packages:
        by_version.setdefault((pkg.version or "").strip(), []).append(pkg)
    for same in by_version.values():
        union = Package(name=same[0].name, version="", ecosystem=same[0].ecosystem)
        for pkg in same:
            _merge_vulns(union, pkg)
        purl = next((p.purl for p in same if p.purl), None)
        for pkg in same:
            _merge_vulns(pkg, union)
            if purl and not pkg.purl:
                pkg.purl = purl


def correlate_agents(agents: list[Agent]) -> tuple[list[Agent], CorrelationResult]:
    """Cross-reference packages across agents from multiple sources.

    Correlation is additive: every server keeps its own package occurrences
    and versions. Only exact duplicates *within one server* are collapsed.
    Across servers, occurrences of the same (name, ecosystem, version) share
    vulnerability evidence and purls, and an ``unknown`` version is filled only
    when every cross-source occurrence agrees on a single specific version.

    Args:
        agents: List of Agent objects from all discovery sources.

    Returns:
        (agents, result) — agents with cross-referenced package data + statistics.
    """
    result = CorrelationResult()

    for agent in agents:
        source = agent.source or "local"
        result.source_summary[source] = result.source_summary.get(source, 0) + 1

    if len(result.source_summary) <= 1:
        return agents, result

    pkg_index: dict[tuple[str, str], list[tuple[Agent, MCPServer, Package]]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            result.deduplicated_packages += _dedupe_server_packages(server)
            for pkg in server.packages:
                key = (pkg.name.lower(), pkg.ecosystem.lower())
                pkg_index.setdefault(key, []).append((agent, server, pkg))

    for occurrences in pkg_index.values():
        if len(occurrences) > 1 and len({(a.source or "local") for a, _s, _p in occurrences}) > 1:
            result.cross_source_matches += 1
            _cross_reference([p for _a, _s, p in occurrences])

    return agents, result


def reverse_lookup_sbom_packages(
    sbom_packages: list[Package],
    agents: list[Agent],
) -> dict[str, list[str]]:
    """Given SBOM packages, find which agents/servers they map to.

    This addresses the "SBOM enrichment" requirement: when a user provides
    --sbom, we can tell them which of their agents actually use those packages.

    Args:
        sbom_packages: Packages from SBOM ingestion.
        agents: Agents discovered from local/cloud sources.

    Returns:
        dict mapping package name → list of "agent:server" strings.
    """
    # Build index of known packages from agents
    agent_pkg_index: dict[str, list[str]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                name_lower = pkg.name.lower()
                location = f"{agent.name}:{server.name}"
                if name_lower not in agent_pkg_index:
                    agent_pkg_index[name_lower] = []
                agent_pkg_index[name_lower].append(location)

    # Match SBOM packages to agents
    matches: dict[str, list[str]] = {}
    for sbom_pkg in sbom_packages:
        name_lower = sbom_pkg.name.lower()
        if name_lower in agent_pkg_index:
            matches[sbom_pkg.name] = agent_pkg_index[name_lower]

    return matches


def build_source_provenance(agents: list[Agent]) -> dict[str, list[str]]:
    """Build a map of package → list of discovery sources.

    Useful for the "full picture" view: showing that 'langchain==0.1.0'
    was found in AWS Bedrock, the SBOM, AND the Snyk scan.

    Args:
        agents: All agents from all discovery sources.

    Returns:
        dict mapping "name@version" → list of source strings.
    """
    provenance: dict[str, list[str]] = {}
    for agent in agents:
        source = agent.source or "local"
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.name}@{pkg.version}"
                if key not in provenance:
                    provenance[key] = []
                if source not in provenance[key]:
                    provenance[key].append(source)

    return provenance
