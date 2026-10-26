"""Shared ExposurePath projection for file-based report formats."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from agent_bom.canonical_ids import agent_graph_id, mcp_server_graph_id
from agent_bom.models import BlastRadius
from agent_bom.package_utils import canonical_package_key

if TYPE_CHECKING:
    from agent_bom.finding import Finding


def _display_package_name(name: str, version: str | None) -> str:
    """Return the package name without a redundant ``@<version>`` suffix.

    Some ingestion paths store ``name@version`` in ``Package.name``. Builders here
    append the version again, so without stripping the duplicate suffix a package
    named ``form-data@4.0.0`` renders as ``form-data@4.0.0@4.0.0``. The graph node
    label already guards against this via ``split("@")[0]``; this keeps the
    file-report projection consistent.
    """
    name = (name or "").strip()
    version = (version or "").strip()
    if version and name.endswith(f"@{version}"):
        return name[: -(len(version) + 1)]
    return name


def exposure_path_for_finding(
    finding: Finding,
    *,
    rank: int | None = None,
    provenance_source: str = "finding_output",
) -> dict[str, Any]:
    """Return a bounded, report-safe ExposurePath view for a unified Finding."""

    from agent_bom.output.finding_views import package_ecosystem, package_name, package_version

    pkg_name = package_name(finding)
    pkg_version = package_version(finding)
    ecosystem = package_ecosystem(finding)
    display_name = _display_package_name(pkg_name, pkg_version or None)
    package_ref, finding_ref, tool_refs, credential_refs = _graph_node_refs(finding, display_name, pkg_version, ecosystem)
    vuln_id = finding.cve_id or finding.title or finding.asset.name
    source_ref, server_refs = _primary_runtime_spine_for_finding(finding, package_ref)
    target_ref = finding_ref
    hops = _ordered_unique([source_ref, *server_refs, package_ref, target_ref])
    nodes = _ordered_unique([*hops, *tool_refs[:3], *credential_refs[:3]])
    relationships = _relationships_for_finding(
        finding,
        source_ref,
        package_ref,
        finding_ref,
        server_refs,
        tool_refs,
        credential_refs,
    )
    fix = (
        f"Upgrade {display_name} to {finding.fixed_version}"
        if finding.fixed_version
        else "No upstream fix recorded; monitor advisory source"
    )
    proof_bits: list[str] = []
    if finding.affected_agents:
        proof_bits.append(f"{len(finding.affected_agents)} affected agent(s)")
    if finding.affected_servers:
        proof_bits.append(f"{len(finding.affected_servers)} affected server(s)")
    if finding.exposed_tools:
        proof_bits.append(f"{len(finding.exposed_tools)} reachable tool(s)")
    if finding.exposed_credentials:
        proof_bits.append(f"{len(finding.exposed_credentials)} exposed credential reference(s)")
    if finding.is_kev:
        proof_bits.append("CISA KEV")
    if finding.epss_score is not None:
        proof_bits.append(f"EPSS {finding.epss_score:.4f}")

    reachability = finding.reachability or "unknown"
    severity = str(finding.effective_severity() or finding.severity or "unknown")
    path_id_parts = [vuln_id, ecosystem, display_name, pkg_version or "unknown"]
    path: dict[str, Any] = {
        "id": "finding:" + ":".join(_slug(part) for part in path_id_parts),
        "rank": rank,
        "label": f"{display_name}@{pkg_version or '?'} -> {vuln_id}",
        "summary": finding.attack_vector_summary
        or finding.ai_risk_context
        or f"{vuln_id} affects {display_name}@{pkg_version or '?'} with {reachability} reachability.",
        "riskScore": round(float(finding.risk_score or 0.0), 2),
        "severity": severity,
        "source": source_ref,
        "target": target_ref,
        "hops": hops,
        "relationships": relationships,
        "nodeIds": nodes,
        "nodeLabels": _node_labels(finding, source_ref, server_refs, package_ref, display_name, pkg_version, vuln_id),
        "edgeIds": [rel["id"] for rel in relationships],
        "findings": [vuln_id],
        "affectedAgents": list(finding.affected_agents[:10]),
        "affectedServers": list(finding.affected_servers[:10]),
        "reachableTools": list(finding.exposed_tools[:10]),
        "exposedCredentials": list(finding.exposed_credentials[:10]),
        "dependencyContext": {
            "package": display_name,
            "version": pkg_version,
            "ecosystem": ecosystem,
            "direct": finding.evidence.get("package_is_direct"),
            "dependencyDepth": finding.evidence.get("package_dependency_depth"),
            "reachabilityEvidence": finding.evidence.get("package_reachability_evidence"),
        },
        "fix": fix,
        "evidence": proof_bits,
        "provenance": {"source": provenance_source, "graphPersistence": False},
    }
    return {key: value for key, value in path.items() if value is not None}


def _blast_exposure_path_id(br: BlastRadius) -> str:
    vuln = br.vulnerability
    package = br.package
    package_name_value = _display_package_name(package.name, package.version)
    return "blast:" + ":".join(_slug(part) for part in [vuln.id, package.ecosystem, package_name_value, package.version or "unknown"])


def exposure_path_for_report_finding(
    finding: Finding,
    *,
    br: BlastRadius | None = None,
    rank: int | None = None,
) -> dict[str, Any]:
    """Project a unified Finding to a legacy-compatible ExposurePath payload."""
    path = exposure_path_for_finding(finding, rank=rank, provenance_source="blast_radius_output")
    if br is not None:
        path["id"] = _blast_exposure_path_id(br)
    return path


def exposure_path_for_blast_radius(br: BlastRadius, *, rank: int | None = None) -> dict[str, Any]:
    """Return a bounded, report-safe ExposurePath view for a blast-radius item."""
    from agent_bom.finding import blast_radius_to_finding

    return exposure_path_for_report_finding(blast_radius_to_finding(br), br=br, rank=rank)


def _chain_token(hop: str, labels: dict[str, str] | None = None) -> str:
    """Render a single hop ref as a display token, preferring its recorded label."""

    if labels and labels.get(hop):
        return labels[hop]
    if hop.startswith("pkg:") and hop.count(":") >= 2:
        return hop.split(":", 2)[2]
    return hop.rsplit(":", 1)[-1] if ":" in hop else hop


def exposure_path_chain(path: dict[str, Any], *, include_tool: bool = True) -> str:
    """Render the primary trust spine of an ExposurePath as a one-line chain."""

    hops = [hop for hop in (path.get("hops") or []) if hop]
    if not hops:
        return ""

    def first(prefix: str) -> str | None:
        return next((hop for hop in hops if hop.startswith(prefix)), None)

    spine: list[str] = [hops[0]]
    for candidate in (first("server:"), first("pkg:"), path.get("target") or first("vuln:") or first("finding:")):
        if candidate and candidate not in spine:
            spine.append(candidate)
    if include_tool:
        # Tools are side nodes provided by the selected server, not sequential
        # topology hops after the finding. Preserve the established human chain
        # without corrupting the primary graph spine.
        nodes = [node for node in (path.get("nodeIds") or []) if node]
        tool = first("tool:") or next((node for node in nodes if node.startswith("tool:")), None)
        if tool and tool not in spine:
            spine.append(tool)
    labels = path.get("nodeLabels") if isinstance(path.get("nodeLabels"), dict) else None
    return " → ".join(_chain_token(hop, labels) for hop in spine)


def exposure_path_blast_summary(path: dict[str, Any]) -> str:
    """Render ``N cred(s), N tool(s) reachable`` for a single ExposurePath."""

    creds = len(path.get("exposedCredentials") or [])
    tools = len(path.get("reachableTools") or [])
    return f"{creds} cred(s), {tools} tool(s) reachable"


def exposure_path_brief_for_finding(finding: Finding, *, rank: int) -> dict[str, str]:
    """Return compact strings for Markdown/HTML investigation summaries."""

    path = exposure_path_for_finding(finding, rank=rank)
    proof = ", ".join(str(item) for item in path.get("evidence", [])) or "Package finding"
    severity = str(finding.effective_severity() or finding.severity or "unknown").upper()
    return {
        "rank": str(rank),
        "risk": f"{float(finding.risk_score or 0.0):.1f}",
        "severity": severity,
        "path": str(path["label"]),
        "why": str(path["summary"]),
        "proof": proof,
        "fix": str(path["fix"]),
    }


def exposure_path_brief(br: BlastRadius, *, rank: int) -> dict[str, str]:
    """Return compact strings for Markdown/HTML investigation summaries."""

    from agent_bom.finding import blast_radius_to_finding

    return exposure_path_brief_for_finding(blast_radius_to_finding(br), rank=rank)


def _primary_runtime_spine_for_finding(finding: Finding, package_ref: str) -> tuple[str, list[str]]:
    """Choose one evidence-backed agent → MCP server spine for a finding.

    Package, repository, image, SBOM, and AI-inventory wrappers reuse the
    ``Agent``/``MCPServer`` storage shape, but they are not runtime MCP hops.
    Treat them as finding context only. When several real MCP servers are
    affected, select one observed agent/server association instead of splicing
    every affected asset into a single path.
    """

    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    surfaces = evidence.get("affected_server_surfaces")
    if isinstance(surfaces, dict):
        runtime_servers = [server for server in finding.affected_servers if str(surfaces.get(server) or "") == "mcp-server"]
    else:
        # Findings created before surface provenance was added retain their
        # first server as a conservative legacy-compatible spine.
        runtime_servers = list(finding.affected_servers[:1])

    if not runtime_servers:
        return package_ref, []

    primary_server = runtime_servers[0]
    links = [link for link in evidence.get("agent_server_links") or [] if isinstance(link, dict)]
    # Without recorded refs only the name is known, which the builder scopes to the declaring agent.
    fallback_agent = agent_graph_id(finding.affected_agents[0]).removeprefix("agent:") if finding.affected_agents else ""
    server_ref = next(
        (str(link["server_ref"]) for link in links if link.get("server") == primary_server and link.get("server_ref")),
        mcp_server_graph_id(primary_server, agent_key=fallback_agent),
    )
    for link in links:
        agent = str(link.get("agent") or "").strip()
        if str(link.get("server") or "") == primary_server and agent and agent in finding.affected_agents:
            return str(link.get("agent_ref") or agent_graph_id(agent)), [str(link.get("server_ref") or server_ref)]

    if finding.affected_agents:
        return agent_graph_id(finding.affected_agents[0]), [server_ref]
    return server_ref, [server_ref]


def _graph_node_refs(finding: Finding, display_name: str, version: str, ecosystem: str) -> tuple[str, str, list[str], list[str]]:
    """Package, finding, tool and credential refs spelled as graph node ids."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    package_ref = f"pkg:{canonical_package_key(display_name, version or 'unknown', ecosystem, evidence.get('package_purl') or None)}"
    finding_ref = f"vuln:{finding.cve_id}" if finding.cve_id else f"finding:{finding.title or finding.asset.name}"
    tools = _graph_refs(evidence, "graph_tool_refs") or [f"tool:{tool}" for tool in finding.exposed_tools]
    credentials = _graph_refs(evidence, "graph_credential_refs") or [f"credential:{name}" for name in finding.exposed_credentials]
    return package_ref, finding_ref, tools, credentials


def _graph_refs(evidence: dict[str, Any], key: str) -> list[str]:
    refs = evidence.get(key)
    return [str(ref) for ref in refs if str(ref).strip()] if isinstance(refs, list) else []


def _node_labels(
    finding: Finding, source_ref: str, server_refs: list[str], package_ref: str, display_name: str, version: str, vuln_id: str
) -> dict[str, str]:
    """Human labels for graph-id hops, so a chain never renders an opaque id."""
    labels = {package_ref: f"{display_name}@{version}" if version else display_name, source_ref: "", **dict.fromkeys(server_refs, "")}
    links = finding.evidence.get("agent_server_links") if isinstance(finding.evidence, dict) else None
    for link in links if isinstance(links, list) else []:
        if isinstance(link, dict):
            labels.update(
                {
                    str(link.get("agent_ref") or ""): str(link.get("agent") or ""),
                    str(link.get("server_ref") or ""): str(link.get("server") or ""),
                }
            )
    labels[f"vuln:{vuln_id}"] = vuln_id
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    for ref in [*_graph_refs(evidence, "graph_tool_refs"), *_graph_refs(evidence, "graph_credential_refs")]:
        labels[ref] = ref.rsplit(":", 1)[-1]
    return {ref: label for ref, label in labels.items() if ref and label}


def _relationships_for_finding(
    finding: Finding,
    source_ref: str,
    package_ref: str,
    finding_ref: str,
    server_refs: list[str],
    tool_refs: list[str],
    credential_refs: list[str],
) -> list[dict[str, str]]:
    rels: list[dict[str, str]] = []

    def add(rel_type: str, source: str, target: str) -> None:
        rels.append({"id": f"{source}->{rel_type}->{target}", "type": rel_type, "source": source, "target": target})

    for server_ref in server_refs[:1]:
        if source_ref != server_ref:
            add("uses", source_ref, server_ref)
        add("depends_on", server_ref, package_ref)
    if not server_refs and source_ref != package_ref:
        add("depends_on", source_ref, package_ref)
    add("vulnerable_to", package_ref, finding_ref)
    exposure_owner = server_refs[0] if server_refs else source_ref
    for tool_ref in tool_refs[:3]:
        add("provides_tool", exposure_owner, tool_ref)
    for credential_ref in credential_refs[:3]:
        add("exposes_credential", exposure_owner, credential_ref)
    return rels


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def blast_radius_exposure_path(report: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a JSON-report ``blast_radius`` row's exposure path.

    Schema ``1`` rows inline the path; schema ``2`` rows reference
    ``exposure_paths.paths`` by 1-based ``exposure_path_rank``, checked against
    ``exposure_path_id`` (ids can repeat when one package version appears
    under several package keys, the rank cannot).
    """
    inline = row.get("exposure_path")
    if isinstance(inline, dict):
        return inline
    section = report.get("exposure_paths")
    paths = section.get("paths") if isinstance(section, Mapping) else None
    rank = row.get("exposure_path_rank")
    if not isinstance(paths, list) or not isinstance(rank, int) or not 1 <= rank <= len(paths):
        return None
    path = paths[rank - 1]
    return path if isinstance(path, dict) and path.get("id") == row.get("exposure_path_id") else None


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {".", "_", "-"} else "-" for ch in value.lower()).strip("-") or "unknown"
