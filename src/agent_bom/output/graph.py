"""Graph data builders for agent → server → package → CVE relationship visualization.

Produces Cytoscape.js-compatible element lists consumable by:
- The built-in HTML dashboard (``--format html``)
- Standalone graph JSON export (``--format graph``)
- External tools: Cytoscape desktop, Sigma.js, D3.js, Gephi (via conversion)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.graph import SEVERITY_RANK as _SEVERITY_RANK
from agent_bom.graph.node import stable_node_id
from agent_bom.output.finding_views import package_graph_node_id as _package_node_id
from agent_bom.output.graph_html import _CDN_FALLBACK_TAGS as _CDN_FALLBACK_TAGS
from agent_bom.output.graph_html import _GRAPH_HTML_TEMPLATE as _GRAPH_HTML_TEMPLATE
from agent_bom.output.graph_html import _VENDOR_JS_FILES as _VENDOR_JS_FILES
from agent_bom.output.graph_html import _graph_overview as _graph_overview
from agent_bom.output.graph_html import _graph_priority_summary as _graph_priority_summary
from agent_bom.output.graph_html import _html_escape as _html_escape
from agent_bom.output.graph_html import _json_for_script as _json_for_script
from agent_bom.output.graph_html import _sanitize_graph_reference_payload as _sanitize_graph_reference_payload
from agent_bom.output.graph_html import _to_offline_graph_html as _to_offline_graph_html
from agent_bom.output.graph_html import _vendor_script_tags as _vendor_script_tags
from agent_bom.output.graph_policy import _SEVERITY_BADGE as _SEVERITY_BADGE
from agent_bom.output.graph_policy import _graph_policy_finding_elements as _graph_policy_finding_elements
from agent_bom.output.graph_policy import _graph_policy_findings as _graph_policy_findings
from agent_bom.output.graph_policy import _norm_repo_dir as _norm_repo_dir
from agent_bom.output.graph_policy import _PackageVulnSummary as _PackageVulnSummary
from agent_bom.output.graph_policy import _provider_label as _provider_label
from agent_bom.output.graph_policy import _summarize_package_vulns as _summarize_package_vulns
from agent_bom.security import sanitize_launch_command, sanitize_path_label, sanitize_text

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


def build_graph_elements(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"] | None = None,
    include_cve_nodes: bool = True,
    *,
    collapse_cves: bool = False,
) -> list[dict]:
    """Build a Cytoscape.js-compatible element list with provider, agent, server, package, and CVE nodes.

    Node types:
      - ``provider``    — cloud source grouping (AWS, Azure, Databricks, local, etc.)
      - ``agent``       — AI agent
      - ``server_vuln``    — MCP server with vulnerable packages
      - ``server_blocked`` — MCP server blocked by MCP intelligence
      - ``server_intel``   — MCP server with non-blocking MCP intelligence findings
      - ``server_cred``    — MCP server with exposed credentials
      - ``server_clean``   — MCP server, no issues
      - ``credential``  — credential reference exposed by an MCP server
      - ``tool``        — MCP tool reachable through a server
      - ``pkg_vuln``    — vulnerable package summary
      - ``cve``         — individual CVE/advisory

    Edge types (in ``data.type``):
      - ``hosts``       — provider → agent
      - ``uses``        — agent → server
      - ``exposes_cred`` — server → credential
      - ``provides_tool`` — server → tool
      - ``reaches_tool`` — credential → tool
      - ``depends_on``  — server → package
      - ``affects``     — package → CVE
    """
    from agent_bom.output.finding_views import cve_findings, topology_package_key, topology_vuln_dict

    findings = cve_findings(report, blast_radii)
    elements: list[dict] = []
    vuln_pkg_keys: set[tuple[str, str, str]] = {topology_package_key(finding) for finding in findings}

    # Track which provider nodes we've already created
    providers_seen: set[str] = set()

    cve_nodes_seen: set[str] = set()

    # Build a lookup: (pkg_name, ecosystem) → list of vulnerability IDs
    pkg_to_vulns: dict[tuple[str, str, str], list[dict]] = {}
    for finding in findings:
        key = topology_package_key(finding)
        if key not in pkg_to_vulns:
            pkg_to_vulns[key] = []
        pkg_to_vulns[key].append(topology_vuln_dict(finding))

    for agent in report.agents:
        # ── Provider node ─────────────────────────────────────────────
        source = agent.source or "local"
        if source not in providers_seen:
            providers_seen.add(source)
            elements.append(
                {
                    "data": {
                        "id": f"provider:{source}",
                        "label": _provider_label(source),
                        "type": "provider",
                        "tip": f"Source: {source}",
                    }
                }
            )

        # ── Agent node ────────────────────────────────────────────────
        aid = f"a:{agent.name}"
        elements.append(
            {
                "data": {
                    "id": aid,
                    "label": agent.name,
                    "type": "agent",
                    "tip": (f"Agent: {agent.name}\nType: {agent.agent_type.value}\nSource: {source}\nServers: {len(agent.mcp_servers)}"),
                    "agentType": agent.agent_type.value,
                    "configPath": sanitize_path_label(agent.config_path) if agent.config_path else "",
                    # "source"/"target" are reserved edge fields in the
                    # Cytoscape element format — a node-level "source" key makes
                    # standards-following consumers misclassify nodes as edges.
                    "discovery_source": source,
                    "serverCount": len(agent.mcp_servers),
                    "packageCount": agent.total_packages,
                    "vulnCount": agent.total_vulnerabilities,
                }
            }
        )
        # Edge: provider → agent
        elements.append(
            {
                "data": {
                    "source": f"provider:{source}",
                    "target": aid,
                    "type": "hosts",
                }
            }
        )

        # ── Server nodes ──────────────────────────────────────────────
        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            vuln_count = sum(1 for p in srv.packages if (p.name, p.ecosystem) in vuln_pkg_keys)
            has_vuln = vuln_count > 0
            has_cred = srv.has_credentials
            has_blocking_intel = bool(getattr(srv, "security_blocked", False))
            has_security_intel = bool(getattr(srv, "security_intelligence", []))
            if has_blocking_intel:
                stype = "server_blocked"
            elif has_vuln:
                stype = "server_vuln"
            elif has_security_intel:
                stype = "server_intel"
            elif has_cred:
                stype = "server_cred"
            else:
                stype = "server_clean"

            vulnerable_pkg_count = sum(1 for p in srv.packages if (p.name, p.ecosystem) in vuln_pkg_keys)
            total_pkg_vulns = 0
            critical_pkg_vulns = 0
            for pkg in srv.packages:
                summary = _summarize_package_vulns(pkg_to_vulns.get((pkg.name, pkg.ecosystem, pkg.version), []))
                total_pkg_vulns += int(summary["vulnCount"])
                critical_pkg_vulns += int(summary["counts"]["critical"])  # type: ignore[index]

            pkg_note = f"\nPackages: {len(srv.packages)}"
            if vuln_count:
                pkg_note += f"\nVulnerable packages: {vulnerable_pkg_count}"
                pkg_note += f"\nTotal CVEs: {total_pkg_vulns}"
                if critical_pkg_vulns:
                    pkg_note += f"\nCritical CVEs: {critical_pkg_vulns}"
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f"{len(srv.packages)} pkg"
            if total_pkg_vulns:
                pkg_badge += f" • {total_pkg_vulns} CVEs"
            server_label = f"{srv.name}\n{pkg_badge}"
            if has_blocking_intel:
                server_label = "BLOCK " + server_label
            elif has_security_intel:
                server_label = "INTEL " + server_label
            elif has_cred:
                server_label = "KEY " + server_label
            elif has_vuln:
                server_label = "RISK " + server_label
            intelligence = list(getattr(srv, "security_intelligence", []) or [])
            intelligence_titles = [
                str(item.get("title") or item.get("entry_id") or "")
                for item in intelligence
                if isinstance(item, dict) and (item.get("title") or item.get("entry_id"))
            ][:5]
            intel_note = f"\nMCP intelligence: {', '.join(intelligence_titles)}" if intelligence_titles else ""
            security_warnings = list(getattr(srv, "security_warnings", []) or [])

            elements.append(
                {
                    "data": {
                        "id": sid,
                        "label": server_label,
                        "type": stype,
                        "tip": f"MCP Server: {srv.name}{pkg_note}{cinfo}{intel_note}",
                        "command": sanitize_launch_command(srv.command or "", srv.args or [], max_args=3)[:80],
                        "packageCount": len(srv.packages),
                        "vulnPackageCount": vulnerable_pkg_count,
                        "vulnCount": total_pkg_vulns,
                        "criticalCount": critical_pkg_vulns,
                        "securityBlocked": has_blocking_intel,
                        "securityIntelligenceCount": len(intelligence),
                        "securityIntelligence": json.dumps(intelligence_titles),
                        "securityWarnings": json.dumps(security_warnings[:5]),
                        "hasCredentials": has_cred,
                        "credentials": json.dumps(srv.credential_names) if srv.credential_names else "[]",
                        "toolNames": json.dumps([t.name for t in srv.tools[:10]]) if srv.tools else "[]",
                    }
                }
            )
            # Edge: agent → server
            elements.append(
                {
                    "data": {
                        "source": aid,
                        "target": sid,
                        "type": "uses",
                        "credentialEdge": 1 if has_cred else 0,
                        "securityBlocked": 1 if has_blocking_intel else 0,
                        "securityIntelligence": 1 if has_security_intel else 0,
                    }
                }
            )

            tool_ids: list[tuple[str, str]] = []
            for tool in srv.tools:
                tool_id = f"tool:{agent.name}:{srv.name}:{tool.name}"
                tool_ids.append((tool.name, tool_id))
                elements.append(
                    {
                        "data": {
                            "id": tool_id,
                            "label": tool.name,
                            "type": "tool",
                            "tip": f"MCP Tool: {tool.name}\nServer: {srv.name}",
                            "server": sid,
                            "searchText": " ".join([tool.name, srv.name, agent.name]).lower(),
                        }
                    }
                )
                elements.append(
                    {
                        "data": {
                            "source": sid,
                            "target": tool_id,
                            "type": "provides_tool",
                        }
                    }
                )

            for cred in srv.credential_names:
                cred_id = f"cred:{agent.name}:{srv.name}:{cred}"
                elements.append(
                    {
                        "data": {
                            "id": cred_id,
                            "label": cred,
                            "type": "credential",
                            "tip": f"Credential: {cred}\nServer: {srv.name}",
                            "server": sid,
                            "searchText": " ".join([cred, srv.name, agent.name]).lower(),
                        }
                    }
                )
                elements.append(
                    {
                        "data": {
                            "source": sid,
                            "target": cred_id,
                            "type": "exposes_cred",
                        }
                    }
                )
                for tool_name, tool_id in tool_ids:
                    elements.append(
                        {
                            "data": {
                                "source": cred_id,
                                "target": tool_id,
                                "type": "reaches_tool",
                                "relationship": "reaches_tool",
                                "server": sid,
                                "credential_env_var": cred,
                                "tool": tool_name,
                                "mapping_method": "server_scope_conservative",
                                "confidence": "medium",
                            }
                        }
                    )

            # ── Package nodes (vulnerable only) ───────────────────────
            seen_pkg_ids: set[str] = set()
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem, pkg.version)
                if pkg_key not in vuln_pkg_keys:
                    continue

                pid = _package_node_id(
                    *pkg_key,
                    agent_name=agent.name,
                    server_name=srv.name,
                    scoped=collapse_cves,
                )
                if pid in seen_pkg_ids:
                    # Just add another edge for shared package
                    elements.append(
                        {
                            "data": {
                                "source": sid,
                                "target": pid,
                                "type": "depends_on",
                            }
                        }
                    )
                    continue
                seen_pkg_ids.add(pid)

                package_vulns = pkg_to_vulns.get(pkg_key, [])
                vuln_summary = _summarize_package_vulns(package_vulns)
                vc = int(vuln_summary["vulnCount"])
                vuln_ids = list(vuln_summary["vulnIds"])
                max_severity = str(vuln_summary["maxSeverity"])
                summary_label = f"{pkg.name}\n{pkg.version}"
                if collapse_cves and vc:
                    summary_label = f"{pkg.name}@{pkg.version}\n{vuln_summary['summaryText']} • {vc} CVEs"
                version_provenance = package_version_provenance(pkg)
                elements.append(
                    {
                        "data": {
                            "id": pid,
                            "label": summary_label,
                            "type": "pkg_vuln",
                            "tip": (
                                f"Package: {pkg.name}\n"
                                f"Version: {pkg.version}\n"
                                f"Ecosystem: {pkg.ecosystem}\n"
                                f"Vulnerabilities: {vc if vc else '(via blast radius)'}\n"
                                f"Highest severity: {max_severity}"
                            ),
                            "ecosystem": pkg.ecosystem,
                            "version": pkg.version,
                            "versionSource": version_provenance.get("version_source", "unknown"),
                            "versionConfidence": version_provenance.get("confidence", "unknown"),
                            "versionProvenance": json.dumps(version_provenance),
                            "vulnIds": json.dumps(vuln_ids),
                            "vulnCount": vc,
                            "maxSeverity": max_severity,
                            "criticalCount": vuln_summary["counts"]["critical"],
                            "highCount": vuln_summary["counts"]["high"],
                            "mediumCount": vuln_summary["counts"]["medium"],
                            "lowCount": vuln_summary["counts"]["low"],
                            "unknownCount": vuln_summary["counts"]["unknown"],
                            "collapsedCves": collapse_cves,
                            "cveList": json.dumps(package_vulns),
                            "searchText": " ".join([pkg.name, pkg.version, pkg.ecosystem, *vuln_ids]).lower(),
                        }
                    }
                )
                # Edge: server → package
                elements.append(
                    {
                        "data": {
                            "source": sid,
                            "target": pid,
                            "type": "depends_on",
                            "versionProvenance": json.dumps(version_provenance),
                            "maxSeverity": max_severity,
                            "vulnCount": vc,
                        }
                    }
                )

                # ── CVE nodes ─────────────────────────────────────────
                if include_cve_nodes and not collapse_cves and pkg_key in pkg_to_vulns:
                    for vuln_info in package_vulns:
                        cve_id = f"cve:{vuln_info['id']}"
                        if cve_id not in cve_nodes_seen:
                            cve_nodes_seen.add(cve_id)
                            sev = vuln_info["severity"]
                            severity_weight = _SEVERITY_RANK.get(sev, 1)
                            elements.append(
                                {
                                    "data": {
                                        "id": cve_id,
                                        "label": f"{vuln_info['id']}\n{sev.upper()}",
                                        "type": "cve",
                                        "kind": "cve",
                                        "tip": (f"{vuln_info['id']}\nSeverity: {sev}\n{vuln_info['summary']}"),
                                        "severity": sev,
                                        "severityClass": f"cve_{sev}",
                                        "severityWeight": severity_weight,
                                        "cvssScore": vuln_info.get("cvss_score", 0),
                                        "summary": vuln_info.get("summary", ""),
                                        "fixVersion": vuln_info.get("fix_version", ""),
                                        "owaspTags": vuln_info.get("owasp_tags", []),
                                        "atlasTags": vuln_info.get("atlas_tags", []),
                                        "nistAiRmfTags": vuln_info.get("nist_ai_rmf_tags", []),
                                        "owaspMcpTags": vuln_info.get("owasp_mcp_tags", []),
                                        "owaspAgenticTags": vuln_info.get("owasp_agentic_tags", []),
                                        "euAiActTags": vuln_info.get("eu_ai_act_tags", []),
                                    }
                                }
                            )
                        # Edge: package → CVE
                        elements.append(
                            {
                                "data": {
                                    "source": pid,
                                    "target": cve_id,
                                    "type": "affects",
                                }
                            }
                        )

    _append_source_tool_elements(elements, report)
    _append_repo_structure_elements(elements, report, collapse_cves=collapse_cves, vuln_pkg_keys=vuln_pkg_keys)
    elements.extend(_graph_policy_finding_elements(report))
    return elements


def _append_source_tool_elements(elements: list[dict], report: "AIBOMReport") -> None:
    """Append AST-discovered tools/application roots and defining source files."""
    inventory = report.ai_inventory_data
    if not isinstance(inventory, dict):
        return
    analysis = inventory.get("ast_analysis")
    if not isinstance(analysis, dict):
        return
    raw_tools = analysis.get("tools")
    raw_entrypoints = analysis.get("application_entrypoints")
    if not isinstance(raw_tools, list):
        raw_tools = []
    if not isinstance(raw_entrypoints, list):
        raw_entrypoints = []
    if not raw_tools and not raw_entrypoints:
        return

    known_nodes = {str(item["data"]["id"]) for item in elements if "id" in item.get("data", {})}
    known_edges = {
        (str(item["data"]["source"]), str(item["data"]["target"]), str(item["data"].get("type", "")))
        for item in elements
        if "source" in item.get("data", {}) and "target" in item.get("data", {})
    }
    for raw in raw_tools:
        if not isinstance(raw, dict):
            continue
        tool_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not tool_name or not source_file:
            continue

        file_id = f"source_file:{source_file}"
        if file_id not in known_nodes:
            known_nodes.add(file_id)
            elements.append(
                {
                    "data": {
                        "id": file_id,
                        "label": source_file.rsplit("/", 1)[-1],
                        "type": "source_file",
                        "path": source_file,
                        "tip": f"Source file: {source_file}",
                        "searchText": source_file.lower(),
                    }
                }
            )

        tool_id = f"tool:source:{stable_node_id(source_file, tool_name)}"
        if tool_id not in known_nodes:
            known_nodes.add(tool_id)
            line = raw.get("line") if isinstance(raw.get("line"), int) else None
            description = sanitize_text(raw.get("description", ""), max_len=1_000)
            handler = sanitize_text(raw.get("handler", ""), max_len=200)
            registration_kind = sanitize_text(raw.get("registration_kind", ""), max_len=100)
            framework = sanitize_text(raw.get("framework", ""), max_len=100)
            provenance = sanitize_text(raw.get("provenance", ""), max_len=500)
            tool_label = "Framework tool" if registration_kind == "framework_tool" else "MCP tool"
            elements.append(
                {
                    "data": {
                        "id": tool_id,
                        "label": tool_name,
                        "type": "tool",
                        "tip": f"{tool_label}: {tool_name}\nSource: {source_file}" + (f":{line}" if line else ""),
                        "description": description,
                        "sourceFile": source_file,
                        "line": line,
                        "handler": handler,
                        "registration_kind": registration_kind,
                        "framework": framework,
                        "provenance": provenance,
                        "discovery_source": "ast_analysis",
                        "searchText": f"{tool_name} {handler} {framework} {source_file} {description}".lower(),
                    }
                }
            )

        edge_key = (file_id, tool_id, "defines")
        if edge_key not in known_edges:
            known_edges.add(edge_key)
            elements.append(
                {
                    "data": {
                        "source": file_id,
                        "target": tool_id,
                        "type": "defines",
                        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                        "registration_kind": sanitize_text(raw.get("registration_kind", ""), max_len=100),
                        "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                        "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                    }
                }
            )

    for raw in raw_entrypoints:
        if not isinstance(raw, dict):
            continue
        entry_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        handler = sanitize_text(raw.get("handler", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not entry_name or not handler or not source_file:
            continue

        file_id = f"source_file:{source_file}"
        if file_id not in known_nodes:
            known_nodes.add(file_id)
            elements.append(
                {
                    "data": {
                        "id": file_id,
                        "label": source_file.rsplit("/", 1)[-1],
                        "type": "source_file",
                        "path": source_file,
                        "tip": f"Source file: {source_file}",
                        "searchText": source_file.lower(),
                    }
                }
            )

        entry_id = f"application_entrypoint:source:{stable_node_id(source_file, entry_name, handler)}"
        if entry_id not in known_nodes:
            known_nodes.add(entry_id)
            line = raw.get("line") if isinstance(raw.get("line"), int) else None
            kind = sanitize_text(raw.get("kind", "application_entrypoint"), max_len=100)
            framework = sanitize_text(raw.get("framework", ""), max_len=100)
            provenance = sanitize_text(raw.get("provenance", ""), max_len=500)
            elements.append(
                {
                    "data": {
                        "id": entry_id,
                        "label": entry_name,
                        "type": "application_entrypoint",
                        "entrypointKind": kind,
                        "handler": handler,
                        "framework": framework,
                        "provenance": provenance,
                        "tip": f"Application entrypoint: {entry_name}\nHandler: {handler}\nSource: {source_file}"
                        + (f":{line}" if line else ""),
                        "sourceFile": source_file,
                        "line": line,
                        "discovery_source": "ast_analysis",
                        "searchText": f"{entry_name} {handler} {kind} {framework} {source_file}".lower(),
                    }
                }
            )

        edge_key = (file_id, entry_id, "defines")
        if edge_key not in known_edges:
            known_edges.add(edge_key)
            elements.append(
                {
                    "data": {
                        "source": file_id,
                        "target": entry_id,
                        "type": "defines",
                        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                    }
                }
            )


def _append_repo_structure_elements(
    elements: list[dict],
    report: "AIBOMReport",
    *,
    collapse_cves: bool,
    vuln_pkg_keys: set[tuple[str, str, str]],
) -> None:
    """Append the repository folder/file structure to a Cytoscape element list.

    Materialises the directory tree (``directory`` nodes linked ``contains``
    parent → child), the manifest / lockfile files each directory holds
    (``config_file`` / ``source_file`` nodes the directory ``contains``), and a
    ``depends_on`` edge from a directory's representative manifest to the
    vulnerable packages discovered for that directory, so a viewer can trace a
    finding back to the file and folder that introduced it. A no-op when the
    report carries no project inventory.
    """
    inventory = report.project_inventory_data
    if not isinstance(inventory, dict):
        return
    directories = inventory.get("directories")
    if not isinstance(directories, list) or not directories:
        return

    code_ext = {
        "py",
        "pyi",
        "js",
        "jsx",
        "ts",
        "tsx",
        "mjs",
        "cjs",
        "go",
        "rs",
        "rb",
        "java",
        "kt",
        "kts",
        "scala",
        "c",
        "cc",
        "cpp",
        "h",
        "hpp",
        "cs",
        "php",
        "swift",
        "m",
        "sh",
        "bash",
    }

    def file_type(name: str) -> str:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return "source_file" if ext in code_ext else "config_file"

    def dir_id(path: str) -> str:
        return "dir:." if path == "" else f"dir:{path}"

    def dir_label(path: str) -> str:
        return "." if path == "" else path.rsplit("/", 1)[-1]

    # Vulnerable package nodes keyed by normalised directory path.
    pkgs_by_dir: dict[str, list[str]] = {}
    for agent in report.agents:
        for srv in agent.mcp_servers:
            dir_path = _norm_repo_dir(srv.name)
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem, pkg.version)
                if pkg_key not in vuln_pkg_keys:
                    continue
                pid = _package_node_id(*pkg_key, agent_name=agent.name, server_name=srv.name, scoped=collapse_cves)
                pkgs_by_dir.setdefault(dir_path, []).append(pid)

    records: dict[str, dict] = {}
    for record in directories:
        if isinstance(record, dict) and isinstance(record.get("path"), str):
            records[_norm_repo_dir(record.get("path"))] = record

    # Every directory plus its ancestors needs a node so the tree is connected.
    needed: set[str] = set()
    for path in records:
        parts = path.split("/") if path else []
        needed.add("")
        for i in range(1, len(parts) + 1):
            needed.add("/".join(parts[:i]))

    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()

    for path in sorted(needed):
        node_id = dir_id(path)
        if node_id in seen_nodes:
            continue
        seen_nodes.add(node_id)
        record = records.get(path, {})
        elements.append(
            {
                "data": {
                    "id": node_id,
                    "label": dir_label(path),
                    "type": "directory",
                    "tip": f"Directory: {path or '.'}\nPackages: {record.get('package_count', 0)}",
                    "path": path or ".",
                    "packageCount": record.get("package_count", 0),
                }
            }
        )
        if path != "":
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            key = (dir_id(parent), node_id)
            if key not in seen_edges:
                seen_edges.add(key)
                elements.append({"data": {"source": key[0], "target": key[1], "type": "contains"}})

    for path in sorted(records):
        record = records[path]
        manifest_files = [f for f in (record.get("manifest_files") or []) if isinstance(f, str)]
        lockfiles = [f for f in (record.get("lockfile_files") or []) if isinstance(f, str)]
        declarations = [f for f in (record.get("declaration_files") or []) if isinstance(f, str)]
        all_files = sorted(set(manifest_files) | set(lockfiles) | set(declarations))
        for file_name in all_files:
            file_path = f"{path}/{file_name}" if path else file_name
            node_id = f"file:{file_path}"
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                elements.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": file_name,
                            "type": file_type(file_name),
                            "tip": f"File: {file_path}",
                            "path": file_path,
                        }
                    }
                )
            key = (dir_id(path), node_id)
            if key not in seen_edges:
                seen_edges.add(key)
                elements.append({"data": {"source": key[0], "target": key[1], "type": "contains"}})

        # Representative manifest → the vulnerable packages this directory holds.
        representative = sorted(declarations or manifest_files or lockfiles)
        if representative and pkgs_by_dir.get(path):
            rep_path = f"{path}/{representative[0]}" if path else representative[0]
            rep_id = f"file:{rep_path}"
            for pid in sorted(set(pkgs_by_dir[path])):
                key = (rep_id, pid)
                if key not in seen_edges:
                    seen_edges.add(key)
                    elements.append({"data": {"source": rep_id, "target": pid, "type": "depends_on"}})


def build_attack_flow_elements(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"] | None = None,
) -> list[dict]:
    """Build a CVE-centric attack flow graph showing how vulns compromise assets.

    Flow direction (left-to-right):
      CVE → Package → MCP Server → Credentials / Tools / Agents

    This is the *reverse* of the supply chain graph — it shows blast radius
    propagation from vulnerability to impacted assets.

    Node types:
      - ``cve``        — CVE/advisory with separate severity metadata
      - ``pkg_vuln``   — vulnerable package
      - ``server``     — MCP server affected
      - ``credential`` — exposed credential (key icon)
      - ``tool``       — reachable MCP tool
      - ``agent``      — affected agent

    Edge types:
      - ``exploits``   — CVE → package
      - ``runs_on``    — package → server
      - ``exposes``    — server → credential
      - ``reaches``    — server → tool
      - ``compromises``— server → agent
    """
    from agent_bom.output.finding_views import cve_findings, package_ecosystem, package_name, package_version, severity_value

    findings = cve_findings(report, blast_radii)
    if not findings:
        return []

    elements: list[dict] = []
    seen_nodes: set[str] = set()

    def _add_node(node_id: str, **data: object) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            elements.append({"data": {"id": node_id, **data}})

    seen_edges: set[tuple[str, str, str]] = set()

    def _add_edge(source: str, target: str, edge_type: str) -> None:
        key = (source, target, edge_type)
        if key not in seen_edges:
            seen_edges.add(key)
            elements.append({"data": {"source": source, "target": target, "type": edge_type}})

    agents_by_name = {agent.name: agent for agent in report.agents}

    for finding in findings:
        sev = severity_value(finding)
        vuln_id = finding.cve_id or finding.title

        # CVE node
        cve_id = f"cve:{vuln_id}"
        score_text = f"\nCVSS: {finding.cvss_score:.1f}" if finding.cvss_score else ""
        fix_text = f"\nFix: {finding.fixed_version}" if finding.fixed_version else "\nNo fix available"
        _add_node(
            cve_id,
            label=vuln_id,
            type="cve",
            kind="cve",
            severity=sev,
            severityClass=f"cve_{sev}",
            tip=f"{vuln_id}\nSeverity: {sev}{score_text}\nBlast score: {finding.risk_score:.1f}{fix_text}",
        )

        # Package node
        pkg_id = _package_node_id(package_name(finding), package_ecosystem(finding), package_version(finding))
        _add_node(
            pkg_id,
            label=f"{package_name(finding)}\n@{package_version(finding)}",
            version=package_version(finding),
            type="pkg_vuln",
            tip=(f"Package: {package_name(finding)}\nVersion: {package_version(finding)}\nEcosystem: {package_ecosystem(finding)}"),
        )
        _add_edge(cve_id, pkg_id, "exploits")

        target_key = (package_name(finding), package_ecosystem(finding), package_version(finding))

        # Servers that use this package
        for agent_name in finding.affected_agents:
            agent = agents_by_name.get(agent_name)
            if not agent:
                continue
            for srv in agent.mcp_servers:
                if finding.affected_servers and srv.name not in finding.affected_servers:
                    continue
                pkg_match = any((p.name, p.ecosystem, p.version) == target_key for p in srv.packages)
                if not pkg_match:
                    continue

                srv_id = f"srv:{agent.name}:{srv.name}"
                _add_node(
                    srv_id,
                    label=srv.name,
                    type="server",
                    tip=f"MCP Server: {srv.name}\nAgent: {agent.name}\nPackages: {len(srv.packages)}",
                )
                _add_edge(pkg_id, srv_id, "runs_on")

                # Exposed credentials
                for cred in srv.credential_names:
                    cred_id = f"cred:{cred}"
                    _add_node(cred_id, label=cred, type="credential", tip=f"Credential: {cred}\nExposed via: {srv.name}")
                    _add_edge(srv_id, cred_id, "exposes")

                # Reachable tools (from introspection data if available)
                tools = getattr(srv, "tool_names", []) or [tool.name for tool in srv.tools]
                for tool_name in tools[:8]:  # cap at 8 to avoid graph explosion
                    tool_id = f"tool:{srv.name}:{tool_name}"
                    _add_node(tool_id, label=tool_name, type="tool", tip=f"MCP Tool: {tool_name}\nServer: {srv.name}")
                    _add_edge(srv_id, tool_id, "reaches")

                # Affected agent
                agent_id = f"agent:{agent.name}"
                _add_node(agent_id, label=agent.name, type="agent", tip=f"Agent: {agent.name}\nType: {agent.agent_type.value}")
                _add_edge(srv_id, agent_id, "compromises")

    return elements


def sanitize_graph_elements(elements: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Redact Cytoscape elements while preserving distinct node coordinates."""
    from agent_bom.output.finding_views import sanitize_output_text
    from agent_bom.security import sanitize_sensitive_payload

    id_map: dict[str, str] = {}
    used_ids: set[str] = set()

    def safe_id(raw: object) -> str:
        original = str(raw)
        existing = id_map.get(original)
        if existing is not None:
            return existing
        candidate = sanitize_output_text(original)
        if candidate in used_ids:
            suffix = 2
            while f"{candidate}#{suffix}" in used_ids:
                suffix += 1
            candidate = f"{candidate}#{suffix}"
        id_map[original] = candidate
        used_ids.add(candidate)
        return candidate

    for element in elements:
        data = element.get("data")
        if isinstance(data, dict) and "source" not in data and "target" not in data and "id" in data:
            safe_id(data["id"])

    projected: list[dict[str, Any]] = []
    for element in elements:
        data = element.get("data")
        if not isinstance(data, dict):
            continue
        safe_data: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                safe_data[key] = sanitize_output_text(value)
            elif isinstance(value, dict | list | tuple):
                safe_data[key] = sanitize_sensitive_payload(value, key=key, max_str_len=10_000)
            else:
                safe_data[key] = value
        if "source" in data or "target" in data:
            if "source" in data:
                safe_data["source"] = safe_id(data["source"])
            if "target" in data:
                safe_data["target"] = safe_id(data["target"])
        elif "id" in data:
            safe_data["id"] = safe_id(data["id"])
        projected.append({**element, "data": safe_data})
    return projected, id_map


def export_graph_html(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"] | None,
    output_path: str,
    *,
    offline_assets: bool = False,
) -> None:
    """Export an interactive standalone HTML file with Cytoscape.js supply chain graph.

    By default, inlines the pinned Cytoscape + dagre bundles vendored with the
    package and embeds data inline, so the export renders fully offline.
    ``offline_assets=True`` emits a static airgap-safe graph summary with no
    scripts at all.
    Supports zoom, pan, click-to-inspect, legend, and PNG export.
    """
    from pathlib import Path

    from agent_bom.output.finding_views import cve_findings

    findings = cve_findings(report, blast_radii)
    policy_findings = _graph_policy_findings(report)
    elements, graph_id_map = sanitize_graph_elements(build_graph_elements(report, blast_radii, include_cve_nodes=False, collapse_cves=True))
    elements_json = _json_for_script(elements)

    total_agents = len(report.agents)
    total_servers = report.total_servers
    total_pkgs = sum(a.total_packages for a in report.agents)
    total_vulns = len(findings)
    all_findings = findings + policy_findings
    top_risks = _sanitize_graph_reference_payload(_graph_priority_summary(all_findings, collapse_cves=True), graph_id_map)
    top_risks_json = _json_for_script(top_risks)
    # The severity chips reconcile with the unified stream: CVE findings plus
    # the graph-derived categories the finding nodes carry.
    overview_json = _json_for_script(_graph_overview(all_findings))
    category_findings = _sanitize_graph_reference_payload(
        [
            {
                "nodeId": f"finding:{finding.id}",
                "category": finding.finding_type.value,
                "severity": str(finding.effective_severity() or "unknown").lower(),
                "title": finding.title,
                "summary": " ".join((finding.description or "").split())[:220],
            }
            for finding in policy_findings
        ],
        graph_id_map,
    )
    category_findings_json = _json_for_script(category_findings)

    html_content = _GRAPH_HTML_TEMPLATE.format(
        vendor_scripts=_vendor_script_tags(),
        elements_json=elements_json,
        top_risks_json=top_risks_json,
        overview_json=overview_json,
        category_findings_json=category_findings_json,
        total_agents=total_agents,
        total_servers=total_servers,
        total_pkgs=total_pkgs,
        total_vulns=total_vulns,
    )
    if offline_assets:
        html_content = _to_offline_graph_html(
            total_agents=total_agents,
            total_servers=total_servers,
            total_pkgs=total_pkgs,
            total_vulns=total_vulns,
            top_risks=_graph_priority_summary(all_findings, collapse_cves=True),
            overview=_graph_overview(all_findings),
        )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_content, encoding="utf-8")
