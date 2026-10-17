"""ExposurePath queue and deploy gate over the dashboard's attack-path ranking.

Both tools read :func:`agent_bom.graph.attack_path_queue.ranked_queue_page`, the
service behind ``/v1/graph/attack-paths``, so an agent and the dashboard see
the same paths in the same order with the same totals.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from agent_bom.cloud.runtime_graph_evidence import _enrich_loaded_graph_runtime_evidence
from agent_bom.config import GRAPH_INVESTIGATION_NODE_BUDGET, MCP_MAX_RESPONSE_CHARS
from agent_bom.graph.attack_path_queue import AttackPathFilters, QueuePage, attack_path_rank_window, ranked_queue_page
from agent_bom.graph.attack_path_queue_rank import MIN_SEVERITY_CHOICES, path_is_kev, path_rank_fields
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.container import AttackPath
from agent_bom.graph.edge_lookup import _build_edge_lookup
from agent_bom.graph.exposure import _exposure_path_for_attack_path
from agent_bom.graph.exposure_cursor import decode_exposure_cursor
from agent_bom.mcp_errors import CODE_UNSUPPORTED_BACKEND, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json

VIEWS = ("summary", "full")
RISK_SCALE = {
    "riskScore": "0-100 composite path risk",
    "evidenceTier": "0-3: 3 finding reached through an agent entrypoint or credential, 2 finding, 1 credential/tool exposure only, 0 none",
}
_SUMMARY_KEYS = (
    "id",
    "rank",
    "label",
    "riskScore",
    "severity",
    "isKev",
    "evidenceTier",
    "graphReachability",
    "reachability",
    "findings",
    "exposedCredentials",
    "reachableTools",
)
_ENDPOINT_KEYS = ("id", "label", "entityType")
# Summary lists keep their first entries and always carry the full count;
# view="full" returns every value.
SUMMARY_LIST_LIMIT = 5
# Whole-queue searches (filters, deploy gate) read at most this many ranked paths.
SEARCH_PATH_CAP = 200_000
_SUMMARY_LISTS = (("findings", "findingCount"), ("exposedCredentials", "credentialCount"), ("reachableTools", "toolCount"))


@dataclass(frozen=True, slots=True)
class PathQuery:
    min_risk: float = 0.0
    min_severity: str | None = None
    kev: bool | None = None
    has_credential: bool | None = None
    source_type: str | None = None
    target_id: str | None = None
    finding_id: str | None = None
    credential_id: str | None = None
    node_id: str | None = None

    def queue_filters(self) -> AttackPathFilters:
        return AttackPathFilters(min_severity=self.min_severity, has_credential=self.has_credential, source_type=self.source_type)

    def needs_full_set(self) -> bool:
        return bool(self.min_risk > 0 or self.kev is not None or self.target_id or self.finding_id or self.credential_id or self.node_id)

    def active(self) -> dict[str, Any]:
        values = {
            "min_risk": self.min_risk or None,
            "min_severity": self.min_severity,
            "kev": self.kev,
            "has_credential": self.has_credential,
            "source_type": self.source_type,
            "target_id": self.target_id,
            "finding_id": self.finding_id,
            "credential_id": self.credential_id,
            "node_id": self.node_id,
        }
        return {key: value for key, value in values.items() if value is not None}

    def matches(self, path: AttackPath, nodes_by_id: dict[str, Any]) -> bool:
        if float(path.composite_risk or 0.0) < self.min_risk:
            return False
        if self.kev is not None and path_is_kev(path, nodes_by_id) != self.kev:
            return False
        if self.target_id and path.target != self.target_id:
            return False
        if self.node_id and self.node_id not in path.hops:
            return False
        if self.credential_id and self.credential_id not in path.credential_exposure and self.credential_id not in path.hops:
            return False
        if self.finding_id:
            wanted = self.finding_id.lower()
            finding_values = [*path.vuln_ids, *path.finding_ids, *(hop for hop in path.hops if hop.startswith(("vuln:", "misconfig:")))]
            if not any(wanted == str(value).lower() or str(value).lower().endswith(":" + wanted) for value in finding_values):
                return False
        return True


def validate_request(limit: int, max_limit: int, query: PathQuery, view: str) -> str | None:
    if limit < 1 or limit > max_limit:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT, f"limit must be between 1 and {max_limit}", details={"argument": "limit", "value": limit}
        )
    if not 0 <= query.min_risk <= 100:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "min_risk must be between 0 and 100",
            details={"argument": "min_risk", "value": query.min_risk},
        )
    if query.min_severity is not None and query.min_severity not in MIN_SEVERITY_CHOICES:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            f"min_severity must be one of: {', '.join(MIN_SEVERITY_CHOICES)}",
            details={"argument": "min_severity"},
        )
    if view not in VIEWS:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "view must be summary or full", details={"argument": "view"})
    for name in ("source_type", "target_id", "finding_id", "credential_id", "node_id"):
        value = getattr(query, name)
        if value is not None and (len(value) > 512 or "\x00" in value):
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, f"{name} is not a valid identifier", details={"argument": name})
    return None


def _endpoint(ref: dict[str, Any]) -> dict[str, Any]:
    endpoint = {key: ref[key] for key in _ENDPOINT_KEYS if key in ref}
    if endpoint.get("label") == endpoint.get("id"):
        endpoint.pop("label", None)
    return endpoint


def summary_path(path: dict[str, Any]) -> dict[str, Any]:
    """The fields an agent needs to rank, cite and follow up one path."""
    summary = {key: path[key] for key in _SUMMARY_KEYS if key in path}
    summary["source"] = _endpoint(path.get("source") or {})
    summary["target"] = _endpoint(path.get("target") or {})
    # Preserve exact ids and evidence; omit only text already present in the endpoints.
    source_label, target_label = summary["source"].get("label"), summary["target"].get("label")
    if source_label and target_label and summary.get("label") == f"{target_label} via {source_label}":
        summary.pop("label", None)
    node_ids = list(path.get("nodeIds") or [])
    # Source and target are listed once, as endpoints; ``via`` holds the hops between them.
    summary["via"] = node_ids[1:-1]
    summary["hopCount"] = len(node_ids)
    for key, count_key in _SUMMARY_LISTS:
        values = list(path.get(key) or [])
        summary[key] = values[:SUMMARY_LIST_LIMIT]
        summary[count_key] = len(values)
    return summary


def project_paths(
    paths: list[AttackPath],
    *,
    nodes: list[Any],
    edges: list[Any],
    first_rank: int,
    scan_id: str,
    ranks: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Project hydrated paths as ExposurePaths carrying the queue's rank evidence."""
    nodes_by_id = {node.id: node for node in nodes}
    edge_lookup = _build_edge_lookup(edges)
    projected: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        rank = ranks[index] if ranks is not None else first_rank + index
        payload = _exposure_path_for_attack_path(
            path, nodes_by_id=nodes_by_id, edges=edges, rank=rank, scan_id=scan_id, edge_lookup=edge_lookup
        )
        fields = path_rank_fields(path, nodes_by_id)
        payload.update(
            severity=fields["severity"],
            isKev=fields["is_kev"],
            evidenceTier=fields["evidence_tier"],
            graphReachable=fields["graph_reachable"],
            graphReachability=fields["graph_reachability"],
        )
        payload["provenance"] = {"source": "mcp_exposure_paths", "scanId": scan_id}
        projected.append(payload)
    return projected


def graph_evidence_scope(scan_id: str, generation: str | None, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "evidence_scope": source.get("evidence_scope", "current_estate" if scan_id.startswith("current-estate:") else "scan_snapshot"),
        "snapshot_generation": generation,
        "collection_coverage": source.get("collection_coverage", {"status": "unknown"}),
    }


def _empty_message(*, snapshot_total: int, query: PathQuery, derivation_truncated: bool) -> str:
    if derivation_truncated:
        return "No paths found within the graph node budget. No conclusion about the full snapshot can be drawn."
    if snapshot_total == 0:
        return "No exposure paths were recorded or derived for this snapshot. This does not establish that its assets are safe."
    if query.min_risk > 0 and set(query.active()) == {"min_risk"}:
        return f"0 paths matched min_risk={query.min_risk:g}; lower min_risk to inspect lower-risk ExposurePaths."
    return "0 paths matched the current filters."


async def pinned_identity(store: Any, tenant_id: str, scan_id: str | None) -> tuple[str, str] | str:
    try:
        return await asyncio.to_thread(store.snapshot_identity, tenant_id=tenant_id, scan_id=scan_id or "", for_paging=True)
    except NotImplementedError:
        return mcp_error_json(
            CODE_UNSUPPORTED_BACKEND,
            "Exposure paths require generation-pinned graph reads, which this graph backend does not support.",
        )


async def queue_page(store: Any, tenant_id: str, scan_id: str, *, offset: int, limit: int, filters: AttackPathFilters) -> QueuePage:
    return await ranked_queue_page(
        store,
        tenant_id=tenant_id,
        scan_id=scan_id,
        offset=offset,
        limit=limit,
        filters=filters,
        enrich=_enrich_loaded_graph_runtime_evidence,
        node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
    )


async def whole_queue(store: Any, tenant_id: str, scan_id: str, filters: AttackPathFilters) -> QueuePage:
    """Every ranked path matching ``filters``, read in rank-window pages up to ``SEARCH_PATH_CAP``.

    ``QueuePage.covers_all_matches`` says whether the result is the whole
    matching set; callers must not treat a partial set as a complete search.
    """
    window = attack_path_rank_window()
    page = await queue_page(store, tenant_id, scan_id, offset=0, limit=window, filters=filters)
    paths = list(page.ranked.paths)
    while page.ranked.paths and len(paths) < min(page.ranked.total, SEARCH_PATH_CAP):
        following = await queue_page(store, tenant_id, page.ranked.scan_id, offset=len(paths), limit=window, filters=filters)
        if not following.ranked.paths:
            break
        paths.extend(following.ranked.paths)
    return replace(page, ranked=replace(page.ranked, paths=paths[:SEARCH_PATH_CAP]))


SNAPSHOT_CHANGED_MESSAGE = "Graph snapshot changed during the read; retry the request."


async def snapshot_changed(store: Any, tenant_id: str, identity: tuple[str, str], *, has_rows: bool) -> bool:
    """Whether the pinned ``(scan_id, generation)`` moved while a multi-read answer was assembled."""
    pinned_scan_id, generation = identity
    final_identity = await asyncio.to_thread(store.snapshot_identity, tenant_id=tenant_id, scan_id=pinned_scan_id, for_paging=True)
    return tuple(final_identity) != (pinned_scan_id, generation) or (has_rows and not generation)


async def nodes_for(store: Any, tenant_id: str, scan_id: str, node_ids: set[str]) -> list[Any]:
    if not node_ids:
        return []
    return list(await asyncio.to_thread(store.nodes_by_ids, tenant_id=tenant_id, scan_id=scan_id, node_ids=node_ids))


async def hydrate(store: Any, tenant_id: str, scan_id: str, paths: list[AttackPath]) -> tuple[list[Any], list[Any]]:
    hop_ids = {hop for path in paths for hop in path.hops}
    nodes = await nodes_for(store, tenant_id, scan_id, hop_ids)
    edges = await asyncio.to_thread(store.edges_for_node_ids, tenant_id=tenant_id, scan_id=scan_id, node_ids=hop_ids, induced_only=True)
    return nodes, list(edges)


def _queue_revision(page: QueuePage, generation: str | None) -> str:
    ranked = page.ranked
    return hashlib.sha256(
        json.dumps([page.source, ranked.scan_id, generation, ranked.created_at, ranked.snapshot_total]).encode()
    ).hexdigest()


def _encode_cursor(scope: str, scan_id: str, offset: int, revision: str) -> str:
    raw = json.dumps({"v": 1, "scope": scope, "scan": scan_id, "offset": offset, "revision": revision}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


@dataclass(slots=True)
class _Read:
    page: QueuePage
    total: int
    paths: list[AttackPath]
    generation: str
    revision: str
    nodes: list[Any]
    edges: list[Any]
    stats: dict[str, Any]
    projected: list[dict[str, Any]]
    covered: bool = True


async def _filtered_window(
    store: Any, tenant_id: str, scan_id: str, query: PathQuery, offset: int, limit: int
) -> tuple[QueuePage, int, list[AttackPath]]:
    if not query.needs_full_set():
        page = await queue_page(store, tenant_id, scan_id, offset=offset, limit=limit, filters=query.queue_filters())
        return page, page.ranked.total, page.ranked.paths
    page = await whole_queue(store, tenant_id, scan_id, query.queue_filters())
    candidates = page.ranked.paths
    hop_ids = {hop for path in candidates for hop in path.hops} if query.kev is not None else set()
    kev_by_id = {node.id: node for node in await nodes_for(store, tenant_id, page.ranked.scan_id, hop_ids)}
    matched = [path for path in candidates if query.matches(path, kev_by_id)]
    return page, len(matched), matched[offset : offset + limit]


def _search_covers_snapshot(page: QueuePage, query: PathQuery) -> bool:
    """Paged reads count matches in the store; whole-queue filters only see what was read."""
    return page.covers_all_matches if query.needs_full_set() else True


async def _read_exposure(
    store: Any, tenant_id: str, scan_id: str | None, query: PathQuery, offset: int, limit: int, continuation: dict[str, Any]
) -> _Read | str:
    identity = await pinned_identity(store, tenant_id, scan_id)
    if isinstance(identity, str):
        return identity
    pinned_scan_id, generation = identity
    page, total, paths = await _filtered_window(store, tenant_id, pinned_scan_id, query, offset, limit)
    effective_scan_id = page.ranked.scan_id
    revision = _queue_revision(page, generation)
    if continuation and continuation["revision"] != revision:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Exposure snapshot changed; restart the query.")
    nodes, edges = await hydrate(store, tenant_id, effective_scan_id, paths)
    stats = await asyncio.to_thread(store.snapshot_stats, tenant_id=tenant_id, scan_id=effective_scan_id)
    if await snapshot_changed(store, tenant_id, identity, has_rows=bool(paths)):
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Exposure snapshot changed; restart the query.")
    projected = project_paths(paths, nodes=nodes, edges=edges, first_rank=offset + 1, scan_id=effective_scan_id)
    covered = _search_covers_snapshot(page, query)
    return _Read(page, total, paths, generation, revision, nodes, edges, stats, projected, covered)


def _envelope(tenant_id: str, read: _Read, query: PathQuery, view: str, limit: int) -> dict[str, Any]:
    ranked = read.page.ranked
    ranking = dict(ranked.ranking or {})
    lower_bound = read.page.derivation_truncated or not bool(ranking.get("complete", True)) or not read.covered
    payload: dict[str, Any] = {
        "schema_version": "v1",
        "tool": "exposure_paths",
        "tenant_id": tenant_id,
        **graph_evidence_scope(ranked.scan_id, read.generation, read.stats),
        "created_at": ranked.created_at,
        "view": view,
        "total": read.total,
        "snapshot_total": ranked.snapshot_total,
        "count_metadata": {
            "source": read.page.source,
            "total_is_lower_bound": lower_bound,
            "snapshot_total": ranked.snapshot_total,
            "materialized_paths": read.page.materialized_paths,
            "derived_paths": read.page.derived_paths,
        },
        "ranking": ranking,
        "risk_scale": RISK_SCALE,
        "filters": {"limit": limit, "min_risk": query.min_risk, **query.active()},
    }
    if not read.projected:
        payload["message"] = _empty_message(
            snapshot_total=ranked.snapshot_total, query=query, derivation_truncated=read.page.derivation_truncated
        )
    return payload


def _fit(payload: dict[str, Any], read: _Read, *, view: str, offset: int, limit: int, scope: str) -> str:
    """Fit whole path objects into the transport budget; omitted paths stay on the cursor."""
    ranking_complete = bool(payload["ranking"].get("complete", True))
    derivation_truncated = read.page.derivation_truncated
    search_cut = ranking_complete and not derivation_truncated and not read.covered
    selected = read.projected
    while True:
        returned = len(selected)
        has_more = offset + returned < read.total
        payload["paths"] = [summary_path(path) for path in selected] if view == "summary" else selected
        if view == "full":
            node_ids = {node_id for path in selected for node_id in path["nodeIds"]}
            edge_ids = {edge_id for path in selected for edge_id in path["edgeIds"]}
            payload["nodes"] = [node.to_dict() for node in read.nodes if node.id in node_ids]
            payload["edges"] = [edge.to_dict() for edge in read.edges if edge.id in edge_ids]
            payload["stats"] = read.stats
        payload["count"] = returned
        next_cursor = _encode_cursor(scope, read.page.ranked.scan_id, offset + returned, read.revision) if has_more and returned else None
        payload["pagination"] = {"offset": offset, "limit": limit, "returned": returned, "has_more": has_more, "next_cursor": next_cursor}
        reason = (
            "node_budget"
            if derivation_truncated
            else "rank_window"
            if not ranking_complete
            else "search_cap"
            if search_cut
            else "path_page_limit"
            if has_more
            else ""
        )
        payload["completeness"] = graph_completeness(
            returned=returned,
            total=None if derivation_truncated or not ranking_complete or search_cut else read.total,
            truncated=bool(reason),
            reason=reason,
        )
        encoded = json.dumps(payload, separators=(",", ":"), default=str)
        if len(encoded) <= MCP_MAX_RESPONSE_CHARS:
            return encoded
        if returned <= 1:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "One exposure path exceeds the response budget; inspect its snapshot through bounded graph node endpoints.",
            )
        selected = selected[: max(1, returned // 2)]


def _continuation(cursor: str | None, *, scope: str, scan_id: str | None) -> tuple[dict[str, Any], str | None, int] | str:
    if not cursor:
        return {}, scan_id, 0
    try:
        continuation = decode_exposure_cursor(cursor, scope=scope, scan_id=scan_id)
        return continuation, continuation["scan"], continuation["offset"]
    except (ValueError, TypeError, KeyError):
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Invalid exposure cursor; restart the query.")


async def exposure_paths_for_tenant(
    *,
    tenant_id: str,
    scan_id: str | None = None,
    limit: int = 5,
    cursor: str | None = None,
    view: str = "full",
    _get_graph_store: Callable[[], Any],
    _resolve_scan: Callable[..., Any],
    _truncate_response: Callable[[str], str] | None = None,
    **filters: Any,
) -> str:
    """Return the ranked ExposurePath page for an already-authenticated tenant.

    ``filters`` are the :class:`PathQuery` fields (``min_risk``, ``min_severity``,
    ``kev``, ``has_credential``, ``source_type``, ``target_id``, ``finding_id``,
    ``credential_id``, ``node_id``).
    """
    try:
        query = PathQuery(**{key: value for key, value in filters.items() if value is not None})
    except TypeError:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Unknown exposure path filter.")
    query = replace(query, min_risk=float(query.min_risk))
    invalid = validate_request(limit, 100, query, view)
    if invalid:
        return invalid
    if scan_id and "\x00" in scan_id:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Invalid graph snapshot identifier.")
    scan_id, resolution_error = await _resolve_scan(tenant_id, scan_id)
    if resolution_error:
        return resolution_error
    # Cursors locate evidence; authorization always comes from the caller's
    # tenant. Pin the snapshot and filters so a new scan cannot shift page two.
    scope = hashlib.sha256(json.dumps([tenant_id, sorted(query.active().items())], default=str).encode()).hexdigest()
    resumed = _continuation(cursor, scope=scope, scan_id=scan_id)
    if isinstance(resumed, str):
        return resumed
    continuation, scan_id, offset = resumed
    read = await _read_exposure(_get_graph_store(), tenant_id, scan_id, query, offset, limit, continuation)
    if isinstance(read, str):
        return read
    encoded = _fit(_envelope(tenant_id, read, query, view, limit), read, view=view, offset=offset, limit=limit, scope=scope)
    return _truncate_response(encoded) if _truncate_response is not None else encoded


__all__ = [
    "RISK_SCALE",
    "VIEWS",
    "PathQuery",
    "exposure_paths_for_tenant",
    "graph_evidence_scope",
    "hydrate",
    "nodes_for",
    "pinned_identity",
    "snapshot_changed",
    "SEARCH_PATH_CAP",
    "SNAPSHOT_CHANGED_MESSAGE",
    "project_paths",
    "summary_path",
    "whole_queue",
]
