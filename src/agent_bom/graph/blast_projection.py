"""Vulnerability and shared-server projection over bounded per-build indexes."""

from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id, source_ids
from agent_bom.core.severity import SEVERITY_RISK_SCORE
from agent_bom.graph.applicability import aggregate_rows, applicability_from_row, row_finding_ids, stronger_applicability
from agent_bom.graph.build_indexes import BuildIndexes
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.exploitability_projection import project_exploitability
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.package_projection import (
    _add_exploitable_via_edges,
    _blast_radius_package_evidence,
    _blast_radius_package_identity,
    _collect_compliance_tags,
    _package_node_id_from_parts,
    _resolve_affected_package_ids,
    _resolve_affected_server_ids,
)
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType

_VULNERABLE_TO = relationship_spec(RelationshipType.VULNERABLE_TO)


def project_package_exploits(graph: UnifiedGraph, indexes: BuildIndexes, data_source_tag: str) -> None:
    for vuln_node_id, srv_id, pkg_id, package_evidence, severity in indexes.pending_exploitable_edges:
        _add_exploitable_via_edges(
            graph,
            server_to_tool_ids=indexes.server_to_tool_ids,
            vuln_node_id=vuln_node_id,
            server_id=srv_id,
            package_id=pkg_id,
            evidence=package_evidence,
            severity=severity,
            data_source=data_source_tag,
        )


def _add_blast_node(
    graph: UnifiedGraph, br_dict: dict[str, Any], vuln_node_id: str, vuln_id_str: str, severity: str, data_source_tag: str
) -> None:
    graph.add_node(
        UnifiedNode(
            id=vuln_node_id,
            entity_type=EntityType.VULNERABILITY,
            label=vuln_id_str,
            severity=severity,
            risk_score=br_dict.get("risk_score", 0),
            attributes={
                "canonical_id": canonical_graph_node_id(EntityType.VULNERABILITY.value, vuln_node_id),
                "source_ids": source_ids(vulnerability_id=vuln_id_str),
                "vulnerability_id": vuln_id_str,
                **(
                    {"finding_id": str(br_dict["finding_id"]).strip()}
                    if isinstance(br_dict.get("finding_id"), str) and str(br_dict.get("finding_id") or "").strip()
                    else {}
                ),
                "cvss_score": br_dict.get("cvss_score"),
                "cvss_vector": br_dict.get("cvss_vector"),
                "attack_vector": br_dict.get("attack_vector"),
                "attack_complexity": br_dict.get("attack_complexity"),
                "privileges_required": br_dict.get("privileges_required"),
                "user_interaction": br_dict.get("user_interaction"),
                "exploitability_assessment": project_exploitability(br_dict, vuln_node_id),
                "network_exploitable": br_dict.get("network_exploitable", False),
                "epss_score": br_dict.get("epss_score"),
                "is_kev": br_dict.get("is_kev", False),
                "fixed_version": br_dict.get("fixed_version"),
                "impact_category": br_dict.get("impact_category", ""),
                "reachability": br_dict.get("reachability", ""),
                "reachability_basis": list(br_dict.get("reachability_basis") or []),
                "graph_reachable": br_dict.get("graph_reachable"),
                "symbol_reachability": br_dict.get("symbol_reachability"),
                "symbol_reachability_reason": br_dict.get("symbol_reachability_reason"),
                "runtime_dependency_chain": list(br_dict.get("runtime_dependency_chain") or []),
                "dependency_reachable": br_dict.get("dependency_reachable"),
            },
            compliance_tags=_collect_compliance_tags(br_dict),
            data_sources=[data_source_tag],
        )
    )


def _server_vulnerability_evidence(
    graph: UnifiedGraph, br_dict: dict[str, Any], data_source_tag: str, vuln_node_id: str, pkg_ids: Any
) -> dict[str, Any]:
    """Evidence for a server's rollup edge to a vulnerability.

    The package edge is the primary exposure. One-hop consumers rely on the
    server edge, so it names the packages it derives from; owners and counts
    never treat it as a second holder. A name-only server match has no package
    edge and stays primary evidence.
    """
    evidence = _occurrence_evidence(br_dict, data_source_tag)
    derived_via = sorted(
        pkg
        for pkg in pkg_ids
        if any(edge.target == vuln_node_id and edge.relationship == RelationshipType.VULNERABLE_TO for edge in graph.adjacency.get(pkg, []))
    )
    if derived_via:
        evidence["derived_via"] = derived_via
        evidence["tier"] = "derived"
        # The rollup stands for one occurrence per package it derives from.
        evidence["applicability_by_holder"] = {pkg: evidence["applicability"] for pkg in derived_via}
    return evidence


def _occurrence_evidence(br_dict: dict[str, Any], data_source_tag: str) -> dict[str, Any]:
    """Package evidence plus this occurrence's applicability and Finding.id."""
    evidence = _blast_radius_package_evidence(br_dict, data_source_tag)
    evidence["applicability"] = applicability_from_row(br_dict)
    finding_ids = row_finding_ids(br_dict)
    if finding_ids:
        evidence["finding_ids"] = finding_ids
    return evidence


def _add_occurrence_edge(graph: UnifiedGraph, source: str, target: str, weight: float, evidence: dict[str, Any]) -> None:
    """Add an occurrence edge; a second row on the same edge keeps the stronger verdict."""
    stored = next(
        (edge for edge in graph.adjacency.get(source, []) if edge.target == target and edge.relationship == RelationshipType.VULNERABLE_TO),
        None,
    )
    if stored is not None:
        stored.evidence["applicability"] = stronger_applicability(stored.evidence.get("applicability"), evidence["applicability"])
        by_holder = stored.evidence.get("applicability_by_holder")
        if isinstance(by_holder, dict):
            for holder, payload in (evidence.get("applicability_by_holder") or {}).items():
                by_holder[holder] = stronger_applicability(by_holder.get(holder), payload)
        merged = sorted({*(stored.evidence.get("finding_ids") or []), *(evidence.get("finding_ids") or [])})
        if merged:
            stored.evidence["finding_ids"] = merged
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.VULNERABLE_TO, weight=weight, evidence=evidence))


def _add_reported_package(graph: UnifiedGraph, pkg_id: str, name: str, version: str, ecosystem: str, data_source_tag: str) -> None:
    graph.add_node(
        UnifiedNode(
            id=pkg_id,
            entity_type=EntityType.PACKAGE,
            label=f"{name}@{version}" if version else name,
            attributes={
                "version": version,
                "ecosystem": ecosystem,
                "canonical_id": canonical_graph_node_id(EntityType.PACKAGE.value, pkg_id),
            },
            data_sources=[data_source_tag],
        )
    )


def project_blast_radius(graph: UnifiedGraph, blast_data: list[dict[str, Any]], indexes: BuildIndexes, data_source_tag: str) -> None:
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        if not vuln_id_str:
            continue
        severity = br_dict.get("severity", "").lower()
        pkg_name, pkg_version = _blast_radius_package_identity(br_dict)
        ecosystem = br_dict.get("ecosystem", "")

        # Add/merge vuln node (add_node unions compliance_tags if node exists)
        vuln_node_id = f"vuln:{vuln_id_str}"
        _add_blast_node(graph, br_dict, vuln_node_id, vuln_id_str, severity, data_source_tag)

        # Link package → vulnerability
        if pkg_name:
            pkg_id = _package_node_id_from_parts(pkg_name, pkg_version, ecosystem, br_dict.get("package_purl") or br_dict.get("purl"))
            if not graph.has_node(pkg_id):
                # The scan reported this package vulnerable without an inventoried
                # host; the package itself is the asset the finding lands on.
                _add_reported_package(graph, pkg_id, pkg_name, pkg_version, ecosystem, data_source_tag)
            if graph.has_node(pkg_id):
                _add_occurrence_edge(
                    graph, pkg_id, vuln_node_id, SEVERITY_RISK_SCORE.get(severity, 1.0), _occurrence_evidence(br_dict, data_source_tag)
                )

        # Link affected servers → vulnerability using indexed lookups instead
        # of an agent×server cross-product scan.
        affected_server_ids = _resolve_affected_server_ids(
            br_dict,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            ecosystem=ecosystem,
            pkg_key_to_servers=indexes.pkg_key_to_servers,
            server_name_to_agent_servers=indexes.server_name_to_agent_servers,
            agent_to_server_ids=indexes.agent_to_server_ids,
        )
        for srv_id in affected_server_ids:
            pkg_ids = _resolve_affected_package_ids(
                br_dict,
                server_id=srv_id,
                pkg_name=pkg_name,
                pkg_version=pkg_version,
                ecosystem=ecosystem,
                package_id_to_servers=indexes.package_id_to_servers,
            )
            # Static imports fold the server into its SBOM / manifest node, which
            # holds the package but is not itself a vulnerable asset kind.
            server_node = graph.get_node(srv_id)
            if (
                server_node is not None
                and _VULNERABLE_TO is not None
                and _VULNERABLE_TO.allows(server_node.entity_type, EntityType.VULNERABILITY)
            ):
                _add_occurrence_edge(
                    graph,
                    srv_id,
                    vuln_node_id,
                    SEVERITY_RISK_SCORE.get(severity, 1.0),
                    _server_vulnerability_evidence(graph, br_dict, data_source_tag, vuln_node_id, pkg_ids),
                )
            for pkg_id in pkg_ids:
                _add_exploitable_via_edges(
                    graph,
                    server_to_tool_ids=indexes.server_to_tool_ids,
                    vuln_node_id=vuln_node_id,
                    server_id=srv_id,
                    package_id=pkg_id,
                    evidence=_blast_radius_package_evidence(br_dict, data_source_tag),
                    severity=severity,
                    data_source=data_source_tag,
                )


def project_shared_servers(graph: UnifiedGraph, indexes: BuildIndexes) -> None:
    for srv_id, agent_ids in indexes.server_to_agents.items():
        unique = sorted(set(agent_ids))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        UnifiedEdge(
                            source=a1,
                            target=a2,
                            relationship=RelationshipType.SHARES_SERVER,
                            direction="bidirectional",
                            traversable=False,
                            weight=3.0,
                            evidence=edge_evidence("blast-radius", "derived", derived_via="shared_server", server=srv_id),
                        )
                    )


def enrich_blast_radius(graph: UnifiedGraph, blast_data: list[dict[str, Any]]) -> None:
    """Summarise every occurrence on its CVE node; no row overwrites another."""
    rows_by_vuln: dict[str, list[dict[str, Any]]] = {}
    for br_dict in blast_data:
        vuln_id_str = br_dict.get("vulnerability_id", "")
        if vuln_id_str:
            rows_by_vuln.setdefault(f"vuln:{vuln_id_str}", []).append(br_dict)
    for vuln_node_id, rows in rows_by_vuln.items():
        vuln_node = graph.get_node(vuln_node_id)
        if vuln_node:
            vuln_node.attributes.update(aggregate_rows(rows))
