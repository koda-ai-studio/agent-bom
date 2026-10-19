"""Projection of persisted graph paths onto finding-list rows.

The graph store is the durable source for ranked ExposurePaths. Findings are a
separate current-state projection, so this module joins rows against an index
of every evidence-bearing path in the materialized snapshot (built once per
snapshot generation) and leaves unassessed rows unknown instead of inventing
``False`` evidence.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from agent_bom.graph.types import RelationshipType

if TYPE_CHECKING:
    from agent_bom.graph.container import AttackPath
    from agent_bom.graph.ports import GraphStoreProtocol


# Page size for reading a snapshot's paths, and the hard ceiling of paths one
# snapshot index holds (beyond it the projection reports ``truncated``).
MAX_FINDING_REACHABILITY_PATHS = 1000
MAX_SNAPSHOT_REACHABILITY_PATHS = 200_000

# Trace order says which assets one correlated trace touched in sequence. It is
# recorded context, never access or exposure evidence, so a route that needs it
# cannot mark a finding reachable (the same rule attack-path fusion applies).
_TRACE_ORDER_EDGES = frozenset({RelationshipType.TRACE_STEP.value})


@dataclass(frozen=True, slots=True)
class FindingReachabilityProjection:
    rows: list[dict[str, Any]]
    truncated: bool


@dataclass(slots=True)
class _ReachabilityEvidence:
    min_hops: int
    agents: set[str]


def _text(value: object) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _vulnerability_id(value: object) -> str:
    normalized = _text(value)
    if not normalized:
        return ""
    lowered = normalized.lower()
    for prefix in ("vuln:", "finding:"):
        if lowered.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    return normalized.upper()


def _row_vulnerability_ids(row: Mapping[str, Any]) -> set[str]:
    values: list[object] = [row.get("cve_id"), row.get("vulnerability_id")]
    for key in ("cve_ids", "advisory_ids", "aliases", "advisory_aliases"):
        collection = row.get(key)
        if isinstance(collection, list):
            values.extend(collection)
    return {identifier for value in values if (identifier := _vulnerability_id(value))}


def _path_vulnerability_ids(path: AttackPath) -> set[str]:
    values: list[object] = list(path.vuln_ids)
    values.append(path.target)
    values.extend(path.hops)
    return {identifier for value in values if (identifier := _vulnerability_id(value)).startswith(("CVE-", "GHSA-", "MAL-"))}


def _path_has_reachability_evidence(path: AttackPath) -> bool:
    """Return whether a persisted path makes its finding ``graph_reachable``.

    ``graph_reachable`` means any inbound attack path reaches the finding,
    including a structural ``depends_on`` chain from a workload. It is not
    proof of execution: the verdict ladder keeps such a path at ``likely``.
    A route that depends on trace order is never a path, because trace order
    records sequence, not access.
    """

    relationships = {edge.value if isinstance(edge, RelationshipType) else _text(edge).lower() for edge in path.edges}
    return bool(relationships) and not relationships & _TRACE_ORDER_EDGES


def _row_node_ids(row: Mapping[str, Any]) -> set[str]:
    asset_id = _text(row.get("node_id"))
    if asset_id:
        return {asset_id}
    return {node_id for key in ("finding_node_id",) if (node_id := _text(row.get(key)))}


def _row_finding_ids(row: Mapping[str, Any]) -> set[str]:
    return {finding_id for key in ("id", "canonical_id", "finding_id") if (finding_id := _text(row.get(key)))}


def _path_matches_row(path: AttackPath, row: Mapping[str, Any]) -> bool:
    finding_ids = _row_finding_ids(row)
    if finding_ids.intersection(path.finding_ids):
        return True
    if path.finding_ids and finding_ids:
        return False

    if not _row_vulnerability_ids(row).intersection(_path_vulnerability_ids(path)):
        return False

    # When the finding carries graph FKs, require one on the path. This avoids
    # marking every asset-specific occurrence of a shared CVE reachable because
    # a different package/server occurrence has a path.
    row_nodes = _row_node_ids(row)
    if not row_nodes:
        return False
    return bool(row_nodes.intersection({path.source, path.target, *path.hops}))


def _path_hop_distance(path: AttackPath, row: Mapping[str, Any]) -> int:
    hops = list(path.hops)
    if not hops:
        return 0
    try:
        source_index = hops.index(path.source)
    except ValueError:
        source_index = 0

    row_nodes = _row_node_ids(row)
    matching_indexes = [index for index, node_id in enumerate(hops) if node_id in row_nodes]
    if matching_indexes:
        forward = [index - source_index for index in matching_indexes if index >= source_index]
        if forward:
            return min(forward)
    try:
        target_index = hops.index(path.target)
    except ValueError:
        target_index = len(hops) - 1
    return max(0, target_index - source_index)


def _reaching_agents(path: AttackPath) -> set[str]:
    agents = {node_id for node_id in (path.source, *path.hops) if node_id.startswith("agent:")}
    return agents


def project_persisted_graph_reachability(
    rows: list[dict[str, Any]],
    *,
    graph_store: GraphStoreProtocol,
    tenant_id: str,
    scan_id: str | None,
    path_limit: int = MAX_SNAPSHOT_REACHABILITY_PATHS,
) -> FindingReachabilityProjection:
    """Project one bounded, tenant-scoped path read onto a findings page.

    A missing match is not proof of unreachability, particularly when the path
    window is truncated, so non-overlapping rows retain their prior value and
    otherwise remain ``None``.
    """

    projected = [dict(row) for row in rows]
    for row in projected:
        row.setdefault("graph_reachable", None)
        row.setdefault("graph_min_hop_distance", None)
        row.setdefault("graph_reachable_from_agents", [])
    if not projected or not any(_row_vulnerability_ids(row) or _row_finding_ids(row) for row in projected):
        return FindingReachabilityProjection(projected, truncated=False)

    index = _snapshot_index(graph_store, tenant_id=tenant_id, scan_id=scan_id or "", path_limit=path_limit)
    # Rows only carry their job's scan id, which never equals the correlated
    # current-estate snapshot id, so the cross-scan guard applies only when the
    # caller asked for one scan.
    _stamp_rows(projected, index, scan_id=index.scan_id if scan_id else None)
    return FindingReachabilityProjection(projected, truncated=index.truncated)


@dataclass(frozen=True, slots=True)
class _PathIndex:
    scan_id: str
    by_finding: dict[str, list[AttackPath]]
    by_vulnerability: dict[str, list[AttackPath]]
    truncated: bool = False


_INDEX_CACHE: OrderedDict[tuple[str, str, str, int, int], _PathIndex] = OrderedDict()
_INDEX_CACHE_LOCK = threading.Lock()
_INDEX_CACHE_MAX = 16


def clear_reachability_index_cache() -> None:
    with _INDEX_CACHE_LOCK:
        _INDEX_CACHE.clear()


def _build_index(paths: Iterable[AttackPath], *, scan_id: str = "", truncated: bool = False) -> _PathIndex:
    by_finding: dict[str, list[AttackPath]] = {}
    by_vulnerability: dict[str, list[AttackPath]] = {}
    for path in paths:
        if not _path_has_reachability_evidence(path):
            continue
        for finding_id in set(path.finding_ids):
            by_finding.setdefault(finding_id, []).append(path)
        for vulnerability_id in _path_vulnerability_ids(path):
            by_vulnerability.setdefault(vulnerability_id, []).append(path)
    return _PathIndex(scan_id, by_finding, by_vulnerability, truncated)


def _snapshot_index(graph_store: GraphStoreProtocol, *, tenant_id: str, scan_id: str, path_limit: int) -> _PathIndex:
    """Index every evidence-bearing path of one snapshot, built once per generation.

    The cache key is the tenant plus the snapshot's identity (id, creation
    time, path count); a newly saved snapshot changes it. Snapshots are
    immutable once saved, so a per-process cache is safe across workers.
    """
    ceiling = max(1, min(int(path_limit), MAX_SNAPSHOT_REACHABILITY_PATHS))
    effective_scan_id, created_at, _probe, total = graph_store.attack_paths(tenant_id=tenant_id, scan_id=scan_id, offset=0, limit=1)
    key = (tenant_id, str(effective_scan_id or ""), str(created_at or ""), int(total), ceiling)
    with _INDEX_CACHE_LOCK:
        cached = _INDEX_CACHE.get(key)
        if cached is not None:
            _INDEX_CACHE.move_to_end(key)
            return cached
    paths: list[AttackPath] = []
    while len(paths) < min(int(total), ceiling):
        _sid, _created, page, _total = graph_store.attack_paths(
            tenant_id=tenant_id,
            scan_id=str(effective_scan_id or scan_id),
            offset=len(paths),
            limit=min(MAX_FINDING_REACHABILITY_PATHS, ceiling - len(paths)),
        )
        if not page:
            break
        paths.extend(page)
    index = _build_index(paths, scan_id=str(effective_scan_id or ""), truncated=int(total) > len(paths))
    if len(paths) < min(int(total), ceiling):
        return index  # A short read (snapshot replaced mid-walk) is never cached.
    with _INDEX_CACHE_LOCK:
        _INDEX_CACHE[key] = index
        while len(_INDEX_CACHE) > _INDEX_CACHE_MAX:
            _INDEX_CACHE.popitem(last=False)
    return index


def project_attack_path_reachability(
    rows: list[dict[str, Any]],
    paths: Iterable[AttackPath],
    *,
    scan_id: str | None = None,
) -> int:
    """Stamp evidence-bearing ``paths`` onto matching ``rows`` in place.

    Only paths with an observed reachability edge count; topology-only paths
    leave rows untouched. When ``scan_id`` is given, rows stamped with another
    scan are skipped. Returns the number of rows marked reachable.
    """
    return _stamp_rows(rows, _build_index(paths), scan_id=scan_id)


def _stamp_rows(rows: list[dict[str, Any]], path_index: _PathIndex, *, scan_id: str | None) -> int:
    paths_by_finding = path_index.by_finding
    paths_by_vulnerability = path_index.by_vulnerability
    evidence_by_row: dict[int, _ReachabilityEvidence] = {}
    for index, row in enumerate(rows):
        row_scan = _text(row.get("scan_id"))
        if scan_id is not None and row_scan and row_scan != scan_id:
            continue
        candidates: dict[int, AttackPath] = {}
        for finding_id in _row_finding_ids(row):
            candidates.update((id(path), path) for path in paths_by_finding.get(finding_id, ()))
        for vulnerability_id in _row_vulnerability_ids(row):
            candidates.update((id(path), path) for path in paths_by_vulnerability.get(vulnerability_id, ()))
        for path in candidates.values():
            if not _path_matches_row(path, row):
                continue
            distance = _path_hop_distance(path, row)
            evidence = evidence_by_row.get(index)
            if evidence is None:
                evidence = _ReachabilityEvidence(min_hops=distance, agents=set())
                evidence_by_row[index] = evidence
            else:
                evidence.min_hops = min(evidence.min_hops, distance)
            evidence.agents.update(_reaching_agents(path))

    for index, evidence in evidence_by_row.items():
        row = rows[index]
        prior_distance = row.get("graph_min_hop_distance")
        row["graph_reachable"] = True
        row["graph_min_hop_distance"] = (
            min(prior_distance, evidence.min_hops)
            if isinstance(prior_distance, int) and not isinstance(prior_distance, bool) and prior_distance >= 0
            else evidence.min_hops
        )
        prior_agents = row.get("graph_reachable_from_agents")
        if isinstance(prior_agents, list):
            evidence.agents.update(_text(value) for value in prior_agents if _text(value))
        row["graph_reachable_from_agents"] = sorted(evidence.agents)

    return len(evidence_by_row)
