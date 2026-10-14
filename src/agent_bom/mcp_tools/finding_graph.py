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

from agent_bom.graph.attack_path_queue import AttackPathFilters
from agent_bom.graph.container import AttackPath
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


def _path_id(path: AttackPath) -> str:
    return f"{path.source}::{path.target}::{'->'.join(path.hops)}"


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
    matched = [path for path in paths if node_id in path.hops]
    package = str(row.get("package") or "").strip()
    if package and matched:
        matched = [path for path in matched if _package_matches(path, package)] or matched
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
