"""Attack paths materialized once per graph snapshot.

Persistence derives the complete investigation path set (fusion, governance,
credential and component chains) in the same unit as the snapshot write and
stores it in ``graph_attack_paths``. Reads use those rows only when the
snapshot's ``analysis_status["paths"]`` records the current
:data:`DERIVATION_VERSION`; anything else derives on read, so older snapshots
keep their exact behaviour.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from agent_bom.core.severity import severity_rank
from agent_bom.graph.analysis import (
    GraphAnalysisState,
    GraphAnalysisStatus,
    analysis_status_map_from_dict,
    analysis_status_map_to_dict,
)
from agent_bom.graph.attack_path_queue_rank import attack_path_rank_key, path_has_credential, path_severity, source_entity_type
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.path_derivation import _derived_attack_paths

logger = logging.getLogger(__name__)

# Bump whenever derived paths, their order/fields, or the stored queue rank/facets can change for the same snapshot.
DERIVATION_VERSION = 3
PATHS_ANALYSIS_KEY = "paths"

SNAPSHOT_PATH_COLUMNS = (
    "tenant_id",
    "scan_id",
    "snapshot_generation",
    "path_key",
    "path_kind",
    "derivation_version",
    "rank_index",
    "source_node",
    "target_node",
    "hop_count",
    "composite_risk",
    "queue_rank",
    "severity_rank",
    "has_credential",
    "source_type",
    "path_json",
    "computed_at",
)


@dataclass(frozen=True, slots=True)
class SnapshotPath:
    path_key: str
    path_kind: str
    rank_index: int
    path: AttackPath
    # Attack-path queue order and filter facets, fixed at persist so a queue
    # page is an indexed read instead of re-ranking every stored path.
    queue_rank: int = 0
    severity_rank: int = 0
    has_credential: bool = False
    source_type: str = ""


def path_identity(path: AttackPath) -> str:
    """Stable identity of one path: its ordered hops and edge relationships."""
    payload = json.dumps([list(path.hops), list(path.edges)], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]


def occurrence_path_keys(paths: Iterable[AttackPath]) -> Iterator[tuple[str, AttackPath]]:
    """Key each path by :func:`path_identity`; repeats of a chain get ``:<ordinal>``."""
    occurrences: dict[str, int] = {}
    for path in paths:
        identity = path_identity(path)
        ordinal = occurrences.get(identity, 0)
        occurrences[identity] = ordinal + 1
        yield (identity if ordinal == 0 else f"{identity}:{ordinal}"), path


def _detached_copy(path: AttackPath) -> AttackPath:
    return AttackPath.from_dict(path.to_dict())


def derived_attack_paths_with_kinds(graph: UnifiedGraph) -> list[tuple[AttackPath, str]]:
    """Ranked served paths tagged fusion/governance/credential/component."""
    kinds: dict[int, str] = {}
    return [(path, kinds.get(id(path), "component")) for path in _derived_attack_paths(graph, kinds=kinds)]


def materialize_snapshot_paths(graph: UnifiedGraph) -> list[SnapshotPath]:
    """Derive the snapshot's full ranked path set without mutating its fusion rows.

    Derivation adjusts persisted fusion paths in place (reachability, capped
    risk), so it runs over detached copies: the legacy ``attack_paths`` rows
    written in the same save stay byte-identical to what fusion produced.
    Identical hop/edge chains that occur more than once keep every occurrence
    under an ordinal-suffixed key.
    """
    original_paths, original_status = graph.attack_paths, graph.analysis_status
    graph.attack_paths = [_detached_copy(path) for path in original_paths]
    # Derive against the analysis status exactly as a reader will load it.
    loaded_status = analysis_status_map_from_dict(analysis_status_map_to_dict(original_status))
    graph.analysis_status = dict(loaded_status)
    try:
        tagged = derived_attack_paths_with_kinds(graph)
        # Keep analyzer receipts the derivation stamps (e.g. credential reach) so
        # a stored-index read reports the same status a read-time derive would.
        for name, status in graph.analysis_status.items():
            if loaded_status.get(name) != status:
                original_status[name] = status
    finally:
        graph.attack_paths, graph.analysis_status = original_paths, original_status
    nodes = graph.nodes
    queue_order = sorted(range(len(tagged)), key=lambda index: attack_path_rank_key(tagged[index][0], nodes))
    queue_rank = {index: position for position, index in enumerate(queue_order)}
    rows: list[SnapshotPath] = []
    keys = occurrence_path_keys(path for path, _ in tagged)
    for rank_index, ((key, path), (_, kind)) in enumerate(zip(keys, tagged)):
        rows.append(
            SnapshotPath(
                key,
                kind,
                rank_index,
                path,
                queue_rank=queue_rank[rank_index],
                severity_rank=severity_rank(path_severity(path, nodes)),
                has_credential=path_has_credential(path, nodes),
                source_type=source_entity_type(path, nodes),
            )
        )
    return rows


def paths_analysis_status(count: int) -> GraphAnalysisStatus:
    return GraphAnalysisStatus(
        status=GraphAnalysisState.COMPLETE,
        observed={"version": DERIVATION_VERSION, "count": count},
    )


def failed_paths_analysis_status() -> GraphAnalysisStatus:
    return GraphAnalysisStatus(status=GraphAnalysisState.FAILED, reason_codes=("analysis_error",))


def prepare_snapshot_paths(graph: UnifiedGraph) -> list[SnapshotPath]:
    """Materialize paths and stamp ``analysis_status``; a failure only disables the index."""
    try:
        rows = materialize_snapshot_paths(graph)
    except Exception:  # noqa: BLE001 — reads fall back to derive-on-read
        logger.warning("snapshot path materialization failed: analysis_error")
        graph.analysis_status[PATHS_ANALYSIS_KEY] = failed_paths_analysis_status()
        return []
    graph.analysis_status[PATHS_ANALYSIS_KEY] = paths_analysis_status(len(rows))
    return rows


def stored_paths_current(analysis_status: Mapping[str, Any] | None) -> bool:
    """Whether the snapshot's stored path rows match this runtime's derivation."""
    status = (analysis_status or {}).get(PATHS_ANALYSIS_KEY)
    if isinstance(status, GraphAnalysisStatus):
        state, observed = status.status.value, status.observed
    elif isinstance(status, Mapping):
        state, observed = str(status.get("status") or ""), status.get("observed") or {}
    else:
        return False
    return state == GraphAnalysisState.COMPLETE.value and observed.get("version") == DERIVATION_VERSION


def snapshot_path_rows(rows: Iterable[SnapshotPath], *, tenant: str, scan: str, generation: str, now: str) -> Iterator[tuple[Any, ...]]:
    for row in rows:
        payload = row.path.to_dict()
        payload.pop("mitre_technique_ids", None)
        yield (
            tenant,
            scan,
            generation,
            row.path_key,
            row.path_kind,
            DERIVATION_VERSION,
            row.rank_index,
            row.path.source,
            row.path.target,
            len(row.path.hops),
            row.path.composite_risk,
            row.queue_rank,
            row.severity_rank,
            int(row.has_credential),
            row.source_type,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            now,
        )


def path_from_json(raw: Any) -> AttackPath:
    data = raw if isinstance(raw, Mapping) else json.loads(raw)
    return AttackPath.from_dict(dict(data))


@dataclass(frozen=True, slots=True)
class StoredPathSet:
    """Ranked stored paths for one snapshot (``paths`` keeps derivation order)."""

    scan_id: str
    created_at: str
    paths: list[AttackPath]


@dataclass(frozen=True, slots=True)
class StoredQueuePage:
    """One attack-path queue page read in stored queue order."""

    scan_id: str
    created_at: str
    paths: list[AttackPath]
    total: int
    snapshot_total: int


def queue_filter_sql(
    *, placeholder: str, min_severity: str | None, has_credential: bool | None, source_type: str | None
) -> tuple[str, list[Any]]:
    """SQL predicate over the stored queue facets, mirroring ``path_matches_filters``."""
    clauses: list[str] = []
    params: list[Any] = []
    if min_severity:
        clauses.append(f"severity_rank >= {placeholder}")
        params.append(severity_rank(min_severity))
    if has_credential is not None:
        clauses.append(f"has_credential = {placeholder}")
        params.append(int(has_credential))
    if source_type:
        clauses.append(f"source_type = {placeholder}")
        params.append(source_type)
    return "".join(f" AND {clause}" for clause in clauses), params


def _derive_on_read(graph: UnifiedGraph) -> list[AttackPath]:
    return _derived_attack_paths(graph)


def resolve_snapshot_attack_paths(graph: UnifiedGraph, graph_store: Any) -> list[AttackPath]:
    """The snapshot's ranked path set: stored rows when current, else derived now.

    Stored rows are only equivalent to a derivation over the *whole* snapshot,
    so a budget-truncated load or a store without the index derives instead.
    """
    reader = getattr(graph_store, "snapshot_attack_paths", None)
    if reader is not None and stored_paths_current(graph.analysis_status) and not graph.completeness.truncated:
        stored = reader(tenant_id=graph.tenant_id, scan_id=graph.scan_id)
        if stored is not None:
            return list(stored.paths)
    return _derive_on_read(graph)


__all__ = [
    "DERIVATION_VERSION",
    "PATHS_ANALYSIS_KEY",
    "SNAPSHOT_PATH_COLUMNS",
    "SnapshotPath",
    "StoredPathSet",
    "StoredQueuePage",
    "queue_filter_sql",
    "materialize_snapshot_paths",
    "occurrence_path_keys",
    "path_from_json",
    "path_identity",
    "paths_analysis_status",
    "prepare_snapshot_paths",
    "resolve_snapshot_attack_paths",
    "snapshot_path_rows",
    "stored_paths_current",
]
