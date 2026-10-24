"""Project a persisted finding onto the attack paths that carry it.

Finding responses withhold credential and tool names (Tier-A redaction), so an
empty list there means "not shown", not "none". The graph's attack paths hold
the same exposure as named references, which is what ``exposure_paths`` already
returns; this module joins a finding to those paths so ``blast_radius`` and
``finding_detail`` can answer from evidence and say when they cannot.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from agent_bom.graph.attack_path_queue import AttackPathFilters
from agent_bom.graph.container import AttackPath
from agent_bom.graph.exposure import exposure_path_id
from agent_bom.mcp_tools.exposure_queue import whole_queue

_PATH_ID_SAMPLE = 5


def finding_node_id(row: dict[str, Any]) -> str:
    explicit = str(row.get("finding_node_id") or row.get("node_id") or "").strip()
    if explicit:
        return explicit
    advisory = str(row.get("cve_id") or row.get("vulnerability_id") or "").strip()
    return f"vuln:{advisory}" if advisory else ""


def _package_matches(path: AttackPath, package: str) -> bool:
    return any(hop.startswith("pkg:") and (hop.endswith(":" + package) or hop.endswith("/" + package)) for hop in path.hops)


def _agent_name(node_id: str) -> str:
    return unquote(node_id.removeprefix("agent:").rsplit(":", 1)[-1])


def _occurrence_paths(row: dict[str, Any], paths: list[AttackPath]) -> list[AttackPath]:
    """Paths carrying this occurrence, not every path through a shared advisory node.

    A ``vuln:<CVE>`` node is shared by every package and agent the advisory
    affects, so joining on it alone hands one agent's credentials to another.
    Prefer the path's recorded finding ids; otherwise require the row's own
    package node and declaring agents. A filter applies only when the row
    carries its key, and a filter that matches nothing is an answer, not a
    reason to fall back to the unscoped set.
    """
    finding_id = str(row.get("id") or "").strip()
    if finding_id:
        tagged = [path for path in paths if finding_id in (path.finding_ids or [])]
        if tagged:
            return tagged
    asset_node = str(row.get("node_id") or "").strip()
    package = str(row.get("package") or "").strip()
    if asset_node.startswith("pkg:"):
        paths = [path for path in paths if asset_node in path.hops]
    elif package:
        paths = [path for path in paths if _package_matches(path, package)]
    agents = {str(name).strip() for name in row.get("affected_agents") or [] if str(name).strip()}
    if agents:
        paths = [path for path in paths if any(hop.startswith("agent:") and _agent_name(hop) in agents for hop in path.hops)]
    return paths


def _path_id(path: AttackPath) -> str:
    return exposure_path_id(path)


def unavailable(reason: str) -> dict[str, Any]:
    return {"source": "graph_attack_paths", "status": "unavailable", "reason": reason, "matched_paths": None}


async def load_snapshot_paths(*, tenant_id: str, scan_id: str | None, get_store: Callable[[], Any]) -> dict[str, Any]:
    """Every ranked path of the tenant's pinned snapshot, or why it is unavailable."""
    try:
        store = get_store()
        pinned_scan_id, generation = await asyncio.to_thread(
            store.snapshot_identity, tenant_id=tenant_id, scan_id=scan_id or "", for_paging=True
        )
        page = await whole_queue(store, tenant_id, pinned_scan_id, AttackPathFilters())
    except NotImplementedError:
        return {"available": False, "reason": "graph_backend_without_pinned_reads"}
    except Exception:  # broad-except: the persisted finding answer stands without its optional graph join
        return {"available": False, "reason": "graph_store_unavailable"}
    ranking_complete = bool((page.ranked.ranking or {}).get("complete", True))
    return {
        "available": True,
        "scan_id": page.ranked.scan_id,
        "snapshot_generation": generation,
        "paths": page.ranked.paths,
        "complete": ranking_complete and not page.derivation_truncated,
        "path_source": page.source,
    }


def project_finding(row: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """The graph exposure of one finding: reachers, credentials, tools and path ids."""
    if not snapshot.get("available"):
        return unavailable(str(snapshot.get("reason") or "graph_store_unavailable"))
    node_id = finding_node_id(row)
    if not node_id:
        return unavailable("finding_has_no_graph_node")
    paths: list[AttackPath] = snapshot["paths"]
    matched = _occurrence_paths(row, [path for path in paths if node_id in path.hops])
    complete = bool(snapshot["complete"])
    reachers = sorted({path.source for path in matched})
    from_agent = sorted({path.source for path in matched if path.source.startswith("agent:")})
    if matched:
        reachability = "reachable_from_agent" if from_agent else "reachable"
    else:
        reachability = "no_recorded_path" if complete else "not_found_in_searched_paths"
    return {
        "source": "graph_attack_paths",
        "status": "evaluated" if matched or complete else "partial",
        "scan_id": snapshot["scan_id"],
        "snapshot_generation": snapshot["snapshot_generation"],
        "finding_node_id": node_id,
        "searched_paths": len(paths),
        "search_complete": complete,
        "matched_paths": len(matched),
        "graph_reachable": True if matched else (False if complete else None),
        "graph_reachability": reachability,
        "reachers": reachers,
        "reachers_from_agents": from_agent,
        "credential_ids": sorted({credential for path in matched for credential in path.credential_exposure}),
        "tool_ids": sorted({tool for path in matched for tool in path.tool_exposure}),
        "max_path_risk": max((float(path.composite_risk or 0.0) for path in matched), default=None),
        "path_ids": [_path_id(path) for path in matched[:_PATH_ID_SAMPLE]],
        "matched": matched,
    }


def exposure_lists(graph: dict[str, Any]) -> tuple[list[str] | None, list[str] | None]:
    """Credential and tool lists, or ``None`` when the graph could not establish them."""
    if graph.get("status") == "unavailable" or (graph.get("matched_paths") == 0 and not graph.get("search_complete")):
        return None, None
    return list(graph.get("credential_ids") or []), list(graph.get("tool_ids") or [])


def public_graph_block(graph: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in graph.items() if key != "matched"}


__all__ = ["exposure_lists", "finding_node_id", "load_snapshot_paths", "project_finding", "public_graph_block", "unavailable"]
