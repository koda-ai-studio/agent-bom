"""Off-loop graph response builders shared by the graph read routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse, Response

from agent_bom.api.graph_paging import _page_meta, _paginate
from agent_bom.api.graph_presentation import _fix_first_card_for_path, _path_matches_focus, _path_semantic_key, _serialize_attack_path_batch
from agent_bom.api.routes.graph_routes.params import (
    _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
    _GRAPH_QUERY_ABSOLUTE_LIMITS,
    _boundary_edge_count,
    _joined_edges,
)
from agent_bom.graph import AttackPath, EntityType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import analysis_status_map_to_dict
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.interaction_risk_ids import interaction_risk_agent_ids
from agent_bom.graph.path_derivation import _build_edge_lookup, _derived_attack_paths
from agent_bom.graph.scope import GraphScopeKind, select_observed_scope
from agent_bom.graph.snapshot_paths import resolve_snapshot_attack_paths

logger = logging.getLogger("agent_bom.api.routes.graph")


def _encoded_graph_response(payload: dict[str, Any]) -> Response:
    """Encode graph JSON off-loop; FastAPI otherwise revisits every nested field."""
    if str(payload.get("scan_id", "")).startswith("current-estate:"):
        payload = {**payload, "evidence_scope": "current_estate"}
    return JSONResponse(content=jsonable_encoder(payload))


def _sync_attack_path_stats(
    stats: dict[str, Any],
    *,
    total: int,
    paths: list[AttackPath],
    complete: bool = False,
) -> dict[str, Any]:
    """Align ``attack_path_count`` / ``max_attack_path_risk`` with derived paths.

    Topology-only snapshots store zero rows in ``attack_paths`` while serve
    surfaces derive paths on read. Without this sync, ``/v1/graph`` can report
    ``attack_path_count: 0`` next to a non-empty ``/attack-paths`` queue.
    ``complete`` marks ``total`` as the full served set rather than a lower
    bound; read-time derivation adds chains persistence never stored, so the
    served total is then the count of record.
    """
    stored = int(stats.get("attack_path_count") or 0)
    if total and stored == 0:
        return {
            **stats,
            "attack_path_count": total,
            "max_attack_path_risk": max((path.composite_risk for path in paths), default=0.0),
        }
    if complete and total != stored:
        return {**stats, "attack_path_count": total}
    return stats


def _ensure_attack_campaigns(graph: UnifiedGraph, paths: list[AttackPath] | None = None) -> None:
    """Materialise crown-jewel campaigns on the serve path when the store has none.

    Campaigns are computed at build-time fusion but not persisted today, so
    store-backed graphs always load ``attack_campaigns=[]``. Recompute from
    jewel-terminating paths when possible; otherwise run the bounded partitioned
    engine when the estate actually has crown jewels. Empty stays empty — no
    fabrication when there is no sensitivity signal.
    """
    if getattr(graph, "attack_campaigns", None):
        return
    try:
        from agent_bom.graph.attack_path_campaigns import compute_partitioned_campaigns
        from agent_bom.graph.attack_path_fusion import _cluster_small_graph_campaigns, _is_crown_jewel

        candidate_paths = list(paths) if paths is not None else list(graph.attack_paths)
        jewel_paths = [path for path in candidate_paths if (node := graph.nodes.get(path.target)) is not None and _is_crown_jewel(node)]
        if jewel_paths:
            graph.attack_campaigns = _cluster_small_graph_campaigns(graph, jewel_paths)
            return
        if any(_is_crown_jewel(node) for node in graph.nodes.values()):
            result = compute_partitioned_campaigns(graph)
            graph.attack_campaigns = list(result.campaigns)
    except Exception:  # noqa: BLE001 — campaigns are additive; never break investigation reads
        logger.debug("attack campaign serve-path materialisation skipped", exc_info=False)


def _filtered_graph_response(graph: UnifiedGraph, *, offset: int, limit: int) -> dict[str, Any]:
    derived_paths = _derived_attack_paths(graph)
    _ensure_attack_campaigns(graph, derived_paths)
    stats = _sync_attack_path_stats(graph.stats(), total=len(derived_paths), paths=derived_paths, complete=True)
    all_nodes = list(graph.nodes.values())
    paged_nodes, pagination = _paginate(all_nodes, offset, limit)

    paged_ids = {n.id for n in paged_nodes}
    paged_edges = [e for e in graph.edges if e.source in paged_ids and e.target in paged_ids]
    matching_paths = [p for p in derived_paths if p.hops and p.hops[0] in paged_ids]
    kept_paths = matching_paths[:_FILTERED_GRAPH_ATTACK_PATH_LIMIT]
    off_page_hops = {hop for p in kept_paths for hop in p.hops} - paged_ids
    nodes_by_id = {n.id: n for n in paged_nodes}
    nodes_by_id.update({hop: graph.nodes[hop] for hop in off_page_hops if hop in graph.nodes})
    attack_paths = _serialize_attack_path_batch(
        kept_paths,
        graph.edges,
        nodes_by_id=nodes_by_id,
        scan_id=graph.scan_id,
    )
    interaction_risks = []
    for risk in graph.interaction_risks:
        agent_ids = interaction_risk_agent_ids(risk, graph)
        if agent_ids and all(agent_id in paged_ids for agent_id in agent_ids):
            interaction_risks.append(risk.to_dict())

    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "nodes": [n.to_dict() for n in paged_nodes],
        "edges": [e.to_dict() for e in paged_edges],
        "attack_paths": attack_paths,
        "attack_campaigns": [c.to_dict() for c in graph.attack_campaigns],
        "interaction_risks": interaction_risks,
        "stats": stats,
        "pagination": pagination,
        # Two independent reasons a response can be partial: the page limit,
        # and a snapshot that was already bounded at load time. The load-time
        # cap is reported first because it is the wider omission — the page is
        # a window onto whatever survived it.
        "completeness": graph_completeness(
            returned=len(paged_nodes),
            total=graph.completeness.total_nodes if graph.completeness.truncated else len(all_nodes),
            truncated=graph.completeness.truncated or pagination["has_more"],
            reason=("node_budget" if graph.completeness.truncated else "node_page_limit" if pagination["has_more"] else ""),
        ),
        "attack_path_pagination": {
            "total": len(matching_paths),
            "limit": _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
            "has_more": len(matching_paths) > _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
        },
    }


def _overlay_filter_and_respond(
    graph: UnifiedGraph,
    *,
    tenant: str,
    apply_overlay: bool,
    filters: Any,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    """Overlay governance, apply the scoped filter, and serialize — all off-loop.

    Consolidates the governance overlay, ``filtered_view`` derivation and
    response build into one synchronous unit so ``get_graph`` runs zero heavy
    work on the event loop between offloaded calls.

    The overlay is applied BEFORE the scoped filter so governance edges are
    subject to the relationship filter and governance nodes left unconnected in a
    scoped view are pruned with everything else. Best-effort; never breaks read.
    """
    if apply_overlay:
        try:
            from agent_bom.graph.governance_overlay import apply_governance_overlay

            apply_governance_overlay(graph, tenant_id=tenant)
        except Exception:  # noqa: BLE001
            logger.warning("governance overlay failed", exc_info=False)
    filtered = graph.filtered_view(filters)
    return _filtered_graph_response(filtered, offset=offset, limit=limit)


def _fix_first_graph_view_payload(
    graph: UnifiedGraph, *, cve: str, package: str, agent: str, limit: int, graph_store: Any = None
) -> dict[str, Any]:
    from agent_bom.graph.path_ranking import criticality_rank_meta, path_rank_tuple

    available_paths = resolve_snapshot_attack_paths(graph, graph_store)
    _ensure_attack_campaigns(graph, available_paths)
    ranked_paths = sorted(
        (path for path in available_paths if _path_matches_focus(graph, path, cve=cve, package=package, agent=agent)),
        key=lambda path: path_rank_tuple(graph, path),
        reverse=True,
    )
    presentation_paths: list[tuple[AttackPath, list[AttackPath]]] = []
    presentation_index: dict[str, int] = {}
    for path in ranked_paths:
        semantic_key = _path_semantic_key(graph, path)
        existing = presentation_index.get(semantic_key)
        if existing is None:
            presentation_index[semantic_key] = len(presentation_paths)
            presentation_paths.append((path, [path]))
        else:
            presentation_paths[existing][1].append(path)

    cards = []
    edge_lookup = _build_edge_lookup(graph.edges)
    for index, (path, occurrence_paths) in enumerate(presentation_paths[:limit]):
        card = _fix_first_card_for_path(
            graph,
            path,
            index + 1,
            edge_lookup=edge_lookup,
            occurrence_paths=occurrence_paths,
        )
        card["rank_meta"] = criticality_rank_meta(graph, path)
        cards.append(card)
    covered_findings = {finding for card in cards for finding in card["affected"]["findings"]}
    # Crown-jewel fusion campaigns (not remediation ticket campaigns).
    campaigns = [campaign.to_dict() for campaign in getattr(graph, "attack_campaigns", [])[:12]]
    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "cards": cards,
        "attack_campaigns": campaigns,
        "summary": {
            "total_paths": len(available_paths),
            "matched_paths": len(ranked_paths),
            "presentation_paths": len(presentation_paths),
            "collapsed_occurrences": len(ranked_paths) - len(presentation_paths),
            "returned_paths": len(cards),
            "highest_risk": cards[0]["attack_path"]["composite_risk"] if cards else 0.0,
            "covered_findings": len(covered_findings),
            "campaign_count": len(getattr(graph, "attack_campaigns", [])),
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "focus": {
            "cve": cve,
            "package": package,
            "agent": agent,
        },
        "completeness": graph_completeness(
            returned=len(cards),
            total=len(presentation_paths),
            truncated=len(presentation_paths) > len(cards),
            reason="path_card_limit" if len(presentation_paths) > len(cards) else "",
        ),
    }


def _serialize_attack_path_queue(
    *,
    scan_id: str,
    tenant: str,
    created_at: str,
    nodes: list[Any],
    path_edges: list[Any],
    paths: list[AttackPath],
    total: int,
    offset: int,
    limit: int,
    stats: dict[str, Any],
    path_source: str,
    materialized_paths: int,
    derived_paths: int,
    ranked: Any = None,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from agent_bom.graph.attack_path_queue_rank import with_rank_fields

    snapshot_total = ranked.snapshot_total if ranked is not None else total
    nodes_by_id = {node.id: node for node in nodes}
    # Keep consecutive-hop witnesses, including reverse traversal of recorded
    # bidirectional edges. Exclude unrelated chords and reversed directed edges.
    path_pairs = {pair for path in paths for pair in zip(path.hops, path.hops[1:], strict=False)}
    path_edges = [
        edge
        for edge in path_edges
        if (edge.source, edge.target) in path_pairs or (edge.is_bidirectional and (edge.target, edge.source) in path_pairs)
    ]
    # Beyond the rank window only the top stored paths were ranked and filtered,
    # so ``total`` counts matches among them: a lower bound, never "complete".
    ranked_all = ranked is None or bool((ranked.ranking or {}).get("complete", True))
    stats = _sync_attack_path_stats(stats, total=snapshot_total, paths=paths, complete=ranked_all)
    has_more = offset + len(paths) < total
    completeness = graph_completeness(
        returned=len(paths),
        total=total if ranked_all else None,
        truncated=has_more or not ranked_all,
        reason="rank_window" if not ranked_all else "path_page_limit" if has_more else "",
    )
    return {
        "scan_id": scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [node.to_dict() for node in nodes],
        "edges": [edge.to_dict() for edge in path_edges],
        "attack_paths": with_rank_fields(
            paths,
            _serialize_attack_path_batch(paths, path_edges, nodes_by_id=nodes_by_id, scan_id=scan_id, rank_offset=offset),
            nodes_by_id,
        ),
        "interaction_risks": [],
        "stats": stats,
        "pagination": _page_meta(total, offset, limit),
        "completeness": completeness,
        "count_metadata": {
            "definition": "Ranked persisted attack paths when available, otherwise paths derived from traversable graph topology.",
            "source": path_source,
            "scope": "tenant graph snapshot",
            "window": {"snapshot_created_at": created_at},
            "filters": {"scan_id": scan_id, "offset": offset, "limit": limit, **(filters or {})},
            "returned": len(paths),
            "total": total,
            "total_is_lower_bound": not ranked_all,
            # Additive, explicitly named counts let clients distinguish the
            # snapshot's source rows from the page transferred over HTTP and
            # from the smaller subset they may choose to render.
            "snapshot_total": snapshot_total,
            "materialized_paths": materialized_paths,
            "derived_paths": derived_paths,
            "returned_rows": len(paths),
            "completeness": completeness,
            **({"ranking": ranked.ranking} if ranked is not None and ranked.ranking else {}),
        },
    }


def _governance_graph_payload(
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    overlay_stats: dict[str, Any],
    node_limit: int,
    edge_limit: int,
    attack_path_limit: int,
    graph_store: Any = None,
) -> dict[str, Any]:
    governance_types = {
        EntityType.MANAGED_IDENTITY,
        EntityType.ACCESS_GRANT,
        EntityType.ACCESS_POLICY,
        EntityType.DRIFT_INCIDENT,
    }
    governance_ids = {node.id for node in graph.nodes.values() if node.entity_type in governance_types}
    keep_edges = [e for e in graph.edges if e.source in governance_ids or e.target in governance_ids]
    keep_ids = set(governance_ids)
    for edge in keep_edges:
        keep_ids.add(edge.source)
        keep_ids.add(edge.target)
    nodes = [graph.nodes[nid].to_dict() for nid in keep_ids if nid in graph.nodes][:node_limit]
    node_id_window = {n["id"] for n in nodes}
    candidate_edges = [e for e in keep_edges if e.source in node_id_window and e.target in node_id_window]
    edges = candidate_edges[:edge_limit]

    # The live overlay can add governance topology the persisted index never saw.
    overlay_changed = any(int(overlay_stats.get(key) or 0) for key in ("nodes_added", "edges_added"))
    source_paths = _derived_attack_paths(graph) if overlay_changed else resolve_snapshot_attack_paths(graph, graph_store)
    matching_paths = [p for p in source_paths if p.hops and any(hop in governance_ids for hop in p.hops)]
    attack_paths = _serialize_attack_path_batch(
        matching_paths[:attack_path_limit],
        keep_edges,
        nodes_by_id=graph.nodes,
        scan_id=graph.scan_id,
    )
    counts: dict[str, int] = {}
    for node in graph.nodes.values():
        if node.entity_type in governance_types:
            counts[node.entity_type.value] = counts.get(node.entity_type.value, 0) + 1
    governance_truncated = len(nodes) < len(keep_ids) or len(edges) < len(candidate_edges) or len(attack_paths) < len(matching_paths)
    return {
        "scan_id": graph.scan_id,
        "tenant_id": tenant_id,
        "created_at": graph.created_at,
        "nodes": nodes,
        "edges": [e.to_dict() for e in edges],
        "attack_paths": attack_paths,
        "overlay": overlay_stats,
        "governance_counts": counts,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "analysis_status": analysis_status_map_to_dict(graph.analysis_status),
        },
        "edge_pagination": {
            "total": len(candidate_edges),
            "limit": edge_limit,
            "has_more": len(candidate_edges) > edge_limit,
        },
        "attack_path_pagination": {
            "total": len(matching_paths),
            "limit": attack_path_limit,
            "has_more": len(matching_paths) > attack_path_limit,
        },
        "completeness": graph_completeness(
            returned=len(nodes),
            total=len(keep_ids),
            truncated=governance_truncated,
            reason="governance_budget" if governance_truncated else "",
        ),
    }


def _scoped_graph_response(
    graph: UnifiedGraph,
    *,
    scope: GraphScopeKind,
    scope_id: str | None,
    max_depth: int,
    limit: int,
) -> dict[str, Any]:
    selected = select_observed_scope(
        graph,
        kind=scope,
        scope_id=scope_id,
        max_depth=max_depth,
        max_nodes=limit,
        max_edges=min(limit * 10, _GRAPH_QUERY_ABSOLUTE_LIMITS["max_edges"]),
    )
    scoped = selected.graph
    result_truncated = selected.node_truncated or graph.completeness.truncated
    node_reason = "source_node_budget" if graph.completeness.truncated else selected.reason if selected.node_truncated else ""
    result_total = None if graph.completeness.truncated else selected.total_nodes
    edge_total = None if graph.completeness.truncated else selected.total_edges
    edge_truncated = graph.completeness.truncated or selected.edge_truncated
    return {
        "scan_id": scoped.scan_id,
        "tenant_id": scoped.tenant_id,
        "created_at": scoped.created_at,
        "scope": {
            "kind": scope,
            "id": scope_id,
            "observed": selected.observed,
            "basis": selected.basis,
        },
        "nodes": [node.to_dict() for node in scoped.nodes.values()],
        "edges": [edge.to_dict() for edge in scoped.edges],
        "stats": scoped.stats(),
        "completeness": {
            "source": graph.completeness.to_dict(),
            "result": graph_completeness(
                returned=len(scoped.nodes),
                total=result_total,
                truncated=result_truncated,
                reason=node_reason,
            ),
            "edges": graph_completeness(
                returned=len(scoped.edges),
                total=edge_total,
                truncated=edge_truncated,
                reason=("source_node_budget" if graph.completeness.truncated else selected.reason if edge_truncated else ""),
            ),
        },
    }


_NODE_PAGE_EDGE_LIMIT = 1000


def _encode_node_page(
    *,
    snapshot_stats: dict,
    total: int,
    paged_nodes: list[UnifiedNode],
    ancestor_nodes: list[UnifiedNode],
    paged_edges: list[UnifiedEdge],
    ancestor_edges: list[UnifiedEdge],
    edges_truncated: bool,
    next_cursor: str | None,
    offset: int,
    limit: int,
    identity: tuple[str, str] | None,
    effective_scan_id: str,
    tenant: str,
    created_at: str,
    source_attack_paths: list[AttackPath],
    nodes_by_id: dict[str, UnifiedNode],
    cursor: str | None,
) -> Response:
    # This branch pages a fully-counted snapshot rather than loading it under a
    # budget, so the estate total IS the stats total. Emitting the field anyway
    # keeps one stats shape across both branches — clients never have to know
    # which path answered them.
    page_stats = {
        **snapshot_stats,
        "total_nodes_source": max(int(snapshot_stats.get("total_nodes", 0)), total),
    }
    response_nodes = [*paged_nodes, *ancestor_nodes]
    response_node_ids = {node.id for node in response_nodes}
    response_edges = _joined_edges(paged_edges, ancestor_edges)
    page_truncated = bool(next_cursor) or offset + len(paged_nodes) < total
    payload = {
        "snapshot_generation": identity[1] if identity else None,
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "collection_coverage": snapshot_stats.get("collection_coverage", {"status": "unknown"}),
        "nodes": [n.to_dict() for n in response_nodes],
        "edges": [e.to_dict() for e in response_edges],
        "attack_paths": _serialize_attack_path_batch(
            source_attack_paths,
            paged_edges,
            nodes_by_id=nodes_by_id,
            scan_id=effective_scan_id,
        ),
        "interaction_risks": [],
        "stats": page_stats,
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
        "completeness": {
            **graph_completeness(
                returned=len(response_nodes),
                total=total,
                truncated=page_truncated or edges_truncated,
                reason="incident_edge_limit" if edges_truncated else "node_page_limit" if page_truncated else "",
            ),
            # ``returned`` counts every node in the payload; ``pagination`` counts
            # only the ranked page. Containment ancestors are added on top of the
            # page, so without naming them the two numbers cannot be reconciled
            # and the extra nodes read as a paging bug.
            "ranked": len(paged_nodes),
            "context_nodes": len(ancestor_nodes),
            "edges_truncated": edges_truncated,
            "edge_limit": _NODE_PAGE_EDGE_LIMIT,
            "edge_returned": len(paged_edges),
            "edge_expansion_endpoint": "/v1/graph/incident-edges",
            # See ``_boundary_edge_count``: the edge list deliberately reaches
            # one hop past the node list, so say by how much rather than letting
            # a client read the payload as an induced subgraph.
            "boundary_edges": _boundary_edge_count(response_edges, response_node_ids),
        },
    }

    return _encoded_graph_response(payload)
