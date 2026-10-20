"""The agent context ``context_graph`` reads from the tenant's current estate graph, one agent page at a time.

The page is the same agent page ``GET /v1/graph?entity_types=agent`` serves
(one ``page_nodes`` read), so an MCP caller and the dashboard see the same
agents. Each agent's servers (``uses``), their packages (``depends_on``),
tools (``provides_tool``), credential names (``exposes_cred``) and the
advisories those packages hold (``vulnerable_to``) are read with bounded
per-hop edge reads. Transitive ``depends_on`` is followed to the holder depth
component paths use; a hop that reaches its bound, or a dependency chain
deeper than that depth, marks the page incomplete.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.stores import _get_graph_store
from agent_bom.graph.component_paths import MAX_HOLDER_DEPTH
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _node_type_value

CONTEXT_PAGE_MAX = 100
HOP_EDGE_LIMIT = 20_000


def _rel(edge: Any) -> str:
    return str(getattr(edge.relationship, "value", edge.relationship))


def _hop(store: Any, read: dict[str, str], sources: set[str], relationships: set[str]) -> tuple[list[Any], bool]:
    """Outgoing edges of ``relationships`` from ``sources``; ``True`` when the bound cut the read."""
    if not sources:
        return [], False
    edges = store.edges_for_node_ids(**read, node_ids=sources, direction="out", relationships=relationships, limit=HOP_EDGE_LIMIT)
    edges = [edge for edge in edges if edge.source in sources and _rel(edge) in relationships]
    return edges, len(edges) >= HOP_EDGE_LIMIT


def _dependency_closure(store: Any, read: dict[str, str], direct: set[str]) -> tuple[dict[str, list[str]], set[str], bool, bool]:
    """``depends_on`` children up to the graph's holder depth; ``(children, packages, depth_limited, edge_cut)``.

    A direct dependency is depth 1, so the walk reads ``MAX_HOLDER_DEPTH - 1``
    further levels, the depth component paths hold an occurrence through.
    """
    children: dict[str, list[str]] = {}
    seen, frontier, cut = set(direct), set(direct), False
    for _level in range(MAX_HOLDER_DEPTH - 1):
        edges, hop_cut = _hop(store, read, frontier, {"depends_on"})
        cut = cut or hop_cut
        following = set()
        for edge in edges:
            children.setdefault(edge.source, []).append(edge.target)
            if edge.target not in seen:
                following.add(edge.target)
        seen |= following
        frontier = following
        if not frontier:
            break
    depth_limited = bool(frontier) and bool(_hop(store, read, frontier, {"depends_on"})[0])
    return children, seen, depth_limited, cut


def _reachable(children: dict[str, list[str]], roots: list[str]) -> list[str]:
    order, seen, stack = [], set(), list(reversed(roots))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        order.append(current)
        stack.extend(reversed(children.get(current, [])))
    return order


def _package_entry(node: UnifiedNode) -> dict[str, Any]:
    attrs = node.attributes or {}
    name = str(attrs.get("name") or attrs.get("package_name") or node.label.rsplit("@", 1)[0])
    version = str(attrs.get("version") or (node.label.rsplit("@", 1)[1] if "@" in node.label[1:] else ""))
    return {"name": name, "version": version, "ecosystem": str(attrs.get("ecosystem") or ""), "purl": attrs.get("purl")}


def _by_source(edges: list[Any]) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    for edge in edges:
        targets.setdefault(edge.source, []).append(edge.target)
    return targets


def estate_context_page(tenant_id: str, *, offset: int = 0, limit: int = 25) -> dict[str, Any] | None:
    """One page of agents with their context, or ``None`` when the tenant has no estate graph agents."""
    store = _get_graph_store()
    limit = max(1, min(int(limit), CONTEXT_PAGE_MAX))
    scan_id, created_at, agents, total, _next = store.page_nodes(tenant_id=tenant_id, entity_types={"agent"}, offset=offset, limit=limit)
    if not total:
        return None
    read = {"tenant_id": tenant_id, "scan_id": scan_id}
    agent_ids = {node.id for node in agents}
    uses, cut_uses = _hop(store, read, agent_ids, {"uses"})
    server_ids = {edge.target for edge in uses}
    server_edges, cut_servers = _hop(store, read, server_ids, {"depends_on", "provides_tool", "exposes_cred"})
    direct = {edge.target for edge in server_edges if _rel(edge) == "depends_on"}
    children, package_ids, depth_limited, cut_deps = _dependency_closure(store, read, direct)
    vuln_edges, cut_vulns = _hop(store, read, package_ids, {"vulnerable_to"})
    wanted = server_ids | package_ids | {edge.target for edge in server_edges} | {edge.target for edge in vuln_edges}
    nodes = {node.id: node for node in store.nodes_by_ids(**read, node_ids=wanted)} if wanted else {}

    servers_of, server_targets, vulns_of = _by_source(uses), _by_source(server_edges), _by_source(vuln_edges)
    report_agents: list[dict[str, Any]] = []
    blast: list[dict[str, Any]] = []
    for agent in agents:
        servers = []
        for server_id in servers_of.get(agent.id, []):
            server = nodes.get(server_id)
            if server is None or _node_type_value(server) != "server":
                continue
            linked = [nodes[target] for target in server_targets.get(server_id, []) if target in nodes]
            reachable = _reachable(children, [node.id for node in linked if _node_type_value(node) == "package"])
            packages = [nodes[pid] for pid in reachable if pid in nodes and _node_type_value(nodes[pid]) == "package"]
            servers.append(
                {
                    "name": server.label,
                    "packages": [_package_entry(node) for node in packages],
                    "tools": [{"name": node.label} for node in linked if _node_type_value(node) == "tool"],
                    "credential_env_vars": [node.label for node in linked if _node_type_value(node) == "credential"],
                }
            )
            for package in packages:
                entry = _package_entry(package)
                for vuln_id in vulns_of.get(package.id, []):
                    vuln = nodes.get(vuln_id)
                    if vuln is None or _node_type_value(vuln) != "vulnerability":
                        continue
                    blast.append(
                        {
                            "vulnerability_id": str((vuln.attributes or {}).get("vulnerability_id") or vuln.label),
                            "severity": vuln.severity or "",
                            "cvss_score": (vuln.attributes or {}).get("cvss_score"),
                            "is_kev": bool((vuln.attributes or {}).get("is_kev")),
                            "package": f"{entry['name']}@{entry['version']}" if entry["version"] else entry["name"],
                            "package_name": entry["name"],
                            "package_version": entry["version"],
                            "ecosystem": entry["ecosystem"],
                            "affected_servers": [server.label],
                            "affected_agents": [agent.label],
                        }
                    )
        agent_type = str((agent.attributes or {}).get("agent_framework") or "")
        report_agents.append({"name": agent.label, "type": agent_type, "mcp_servers": servers})
    return {
        "agents": report_agents,
        "blast_radius": blast,
        "scan_id": scan_id,
        "created_at": created_at,
        "total": int(total),
        "offset": offset,
        "limit": limit,
        "hop_truncated": cut_uses or cut_servers or cut_vulns or cut_deps,
        "depth_limited": depth_limited,
    }


__all__ = ["CONTEXT_PAGE_MAX", "estate_context_page"]
