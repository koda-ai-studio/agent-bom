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

from agent_bom.graph.analysis import (
    GraphAnalysisState,
    GraphAnalysisStatus,
    analysis_status_map_from_dict,
    analysis_status_map_to_dict,
)
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.path_derivation import _derived_attack_paths

logger = logging.getLogger(__name__)

# Bump whenever derived_attack_paths_with_kinds can emit different paths, order or fields for the same snapshot.
DERIVATION_VERSION = 1
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
    "path_json",
    "computed_at",
)


@dataclass(frozen=True, slots=True)
class SnapshotPath:
    path_key: str
    path_kind: str
    rank_index: int
    path: AttackPath


def path_identity(path: AttackPath) -> str:
    """Stable identity of one path: its ordered hops and edge relationships."""
    payload = json.dumps([list(path.hops), list(path.edges)], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]


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
    occurrences: dict[str, int] = {}
    rows: list[SnapshotPath] = []
    for rank_index, (path, kind) in enumerate(tagged):
        identity = path_identity(path)
        ordinal = occurrences.get(identity, 0)
        occurrences[identity] = ordinal + 1
        rows.append(SnapshotPath(identity if ordinal == 0 else f"{identity}:{ordinal}", kind, rank_index, path))
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


def _derive_on_read(graph: UnifiedGraph) -> list[AttackPath]:
    return _derived_attack_paths(graph)


def derived_paths_revision(paths: list[AttackPath]) -> str:
    payload = json.dumps([(p.hops, p.edges, p.composite_risk, p.reachability) for p in paths], sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def exposure_path_page(
    graph_store: Any, *, tenant_id: str, scan_id: str, offset: int, limit: int
) -> tuple[str, str, list[AttackPath], int, str, str]:
    """``(scan_id, created_at, page, total, source, revision)``: index first, else persisted rows."""
    reader = getattr(graph_store, "snapshot_attack_paths", None)
    stored = reader(tenant_id=tenant_id, scan_id=scan_id) if reader is not None else None
    if stored is None:
        effective, created_at, page, total = graph_store.attack_paths(tenant_id=tenant_id, scan_id=scan_id, offset=offset, limit=limit)
        return effective, created_at, page, total, "persisted_graph_paths", ""
    page = stored.paths[offset : offset + limit]
    return stored.scan_id, stored.created_at, page, len(stored.paths), "derived_graph_paths", derived_paths_revision(stored.paths)


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
    "materialize_snapshot_paths",
    "path_from_json",
    "path_identity",
    "paths_analysis_status",
    "prepare_snapshot_paths",
    "resolve_snapshot_attack_paths",
    "snapshot_path_rows",
    "stored_paths_current",
]
