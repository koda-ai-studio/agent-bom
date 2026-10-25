"""What changed in the current estate, behind ``/v1/graph/changes`` and MCP ``graph_diff`` ``view="estate"``.

The current estate is a projection over the newest completed scan per target
scope. A tenant-wide "latest two snapshots" diff therefore compares unrelated
sources. Here every scope's current snapshot is compared with that same
scope's previous completed snapshot, using the bounded ``/v1/graph/diff`` rows,
and the per-scope answers are aggregated. A scope scanned only once falls back
to the store's declared continuity baseline (the earlier same-kind snapshot)
when no other scope's scan owns it. A scope with neither is a first
observation, never an addition.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from agent_bom.api.current_graph import available_sources, graph_scan_id, refuse_unpinned_read_while_seeding
from agent_bom.api.finding_job_metadata import scan_evidence_authority_key, scan_scope_key
from agent_bom.api.finding_row_shapes import _scan_source_labels
from agent_bom.api.graph_diff_read import _compute_rows, _stored_paths
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.stores import _get_store
from agent_bom.graph.attack_path_queue import attack_path_rank_window
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.diff_sources import attribute_highlight_vendors, changes_by_collected_source
from agent_bom.graph.diff_view import diff_summary, new_attack_paths

_logger = logging.getLogger(__name__)

SOURCE_LIMIT_DEFAULT = 50
SOURCE_LIMIT_MAX = 100
# Older snapshots inspected per scope while looking for one with graph evidence.
PREVIOUS_SEARCH_LIMIT = 25
_TARGET_LABEL_KEYS = ("provider", "account", "account_ref", "account_id", "region", "environment", "path", "repo", "name")
_FIELD_LABELS = {"images": "image", "repo_url": "repo", "k8s": "kubernetes", "filesystem_paths": "path", "agent_projects": "project"}


@dataclass(frozen=True)
class _Baseline:
    """The snapshot a scope is compared with, and why it is comparable."""

    scan_id: str
    job_id: str
    captured_at: str
    # "scope_history": the scope's own earlier scan; "snapshot_continuity": the store's declared predecessor.
    basis: str


@dataclass(frozen=True)
class _Scope:
    key: str
    current: Any
    previous: _Baseline | None
    skipped: int
    searched_out: bool


def _completed_jobs(job_store: Any, tenant: str) -> list[Any]:
    summaries = job_store.list_summary(tenant_id=tenant, status=JobStatus.DONE)
    jobs = (job_store.get(row["job_id"], tenant_id=tenant) for row in summaries if not row.get("child_job_ids"))
    return [
        job
        for job in jobs
        if job is not None
        and job.tenant_id == tenant
        and job.status == JobStatus.DONE
        and isinstance(job.result, dict)
        and not job.child_job_ids
    ]


def _has_graph(store: Any, tenant: str, scan_id: str) -> bool:
    return bool(store.snapshot_identity(tenant_id=tenant, scan_id=scan_id, for_paging=True)[1])


def _plan(store: Any, job_store: Any, tenant: str) -> tuple[list[_Scope], set[str]]:
    """Pair each scope's current snapshot with its own previous snapshot that has a graph."""
    jobs = _completed_jobs(job_store, tenant)
    if not jobs:
        # Graph-only (legacy) stores hold snapshots without the scan jobs that define scopes.
        return [], {"scan_history_unavailable"} if store.list_snapshots(tenant_id=tenant, limit=1) else set()
    selected, _revisions, reasons = available_sources(store, tenant, jobs)
    current: dict[str, Any] = {}
    for job in selected:
        scope = scan_scope_key(job)
        if scope not in current or scan_evidence_authority_key(job) > scan_evidence_authority_key(current[scope]):
            current[scope] = job
    history: dict[str, list[Any]] = {}
    owner: dict[str, str] = {}
    for job in jobs:
        history.setdefault(scan_scope_key(job), []).append(job)
        owner.setdefault(graph_scan_id(job), scan_scope_key(job))
    scopes: list[_Scope] = []
    for scope, job in current.items():
        authority, new_id = scan_evidence_authority_key(job), graph_scan_id(job)
        older = sorted(
            (
                other
                for other in history.get(scope, [])
                if scan_evidence_authority_key(other) < authority and graph_scan_id(other) != new_id
            ),
            key=scan_evidence_authority_key,
            reverse=True,
        )
        previous: _Baseline | None = None
        skipped = 0
        for other in older[:PREVIOUS_SEARCH_LIMIT]:
            if _has_graph(store, tenant, graph_scan_id(other)):
                previous = _Baseline(graph_scan_id(other), str(other.job_id), scan_evidence_authority_key(other)[0], "scope_history")
                break
            skipped += 1
        if previous is None and not older:
            previous = _continuity_baseline(store, tenant, new_id, scope, owner)
            if previous is not None:
                reasons.add("snapshot_baseline")
        scopes.append(_Scope(scope, job, previous, skipped, previous is None and len(older) > PREVIOUS_SEARCH_LIMIT))
        if skipped:
            reasons.add("previous_graph_unavailable")
    scopes.sort(key=lambda item: (scan_evidence_authority_key(item.current), item.key), reverse=True)
    return scopes, reasons


def _continuity_baseline(store: Any, tenant: str, scan_id: str, scope: str, owner: dict[str, str]) -> _Baseline | None:
    """The store's earlier same-kind snapshot, unless another scope's scan owns it.

    Snapshot writes already treat this predecessor as the continuity baseline
    for edge history. A snapshot recorded by a different scope is an unrelated
    source and is never compared.
    """
    try:
        candidate = store.previous_snapshot_id(tenant_id=tenant, before_scan_id=scan_id)
    except NotImplementedError:
        return None
    if not candidate or owner.get(candidate, scope) != scope or not _has_graph(store, tenant, candidate):
        return None
    rows = store.snapshots_by_ids(tenant_id=tenant, scan_ids={candidate})
    captured = str(rows[0].get("created_at") or "") if rows else ""
    return _Baseline(candidate, "", captured, "snapshot_continuity")


def _path_changes(store: Any, tenant: str, old_id: str, new_id: str) -> dict[str, Any]:
    """Stored attack paths added and removed between the pair, bounded by the rank window."""
    window = attack_path_rank_window()
    old_paths, old_total = _stored_paths(store, tenant, old_id, window)
    new_paths, new_total = _stored_paths(store, tenant, new_id, window)
    return {
        "new_attack_paths": new_attack_paths(old_paths, new_paths, old_total=old_total, new_total=new_total, window=window),
        "removed_attack_paths": new_attack_paths(new_paths, old_paths, old_total=new_total, new_total=old_total, window=window),
    }


def _label_endpoints(store: Any, tenant: str, old_id: str, new_id: str, highlights: dict[str, Any]) -> None:
    """Name each highlighted path or reach edge's endpoints from the snapshot that holds it."""
    sides = {new_id: [("new_attack_paths", "top"), ("new_credential_reach", "top")], old_id: [("removed_attack_paths", "top")]}
    for scan_id, groups in sides.items():
        rows = [row for key, field in groups for row in (highlights.get(key) or {}).get(field) or []]
        ids = {str(row.get(end) or "") for row in rows for end in ("source", "target")} - {""}
        if not ids:
            continue
        labels = {node.id: node.label for node in store.nodes_by_ids(tenant_id=tenant, scan_id=scan_id, node_ids=ids)}
        for row in rows:
            for end in ("source", "target"):
                node_id = str(row.get(end) or "")
                row[f"{end}_label"] = labels.get(node_id) or node_id


def scope_label(job: Any) -> str:
    """A human scope name (source / provider / account / target), never the opaque scope hash."""
    parts: list[str] = []
    source = str(getattr(job, "source_id", None) or "").strip()
    if source:
        parts.append(source)
    target = getattr(job, "target", None)
    if isinstance(target, dict):
        if "field" in target and "value" in target:
            value = target["value"]
            rendered = value if isinstance(value, str) else ", ".join(f"{key}={item}" for key, item in sorted(dict(value).items()) if item)
            field = str(target["field"])
            parts.append(f"{_FIELD_LABELS.get(field, field)} {rendered}".strip())
        else:
            parts.extend(str(target[key]) for key in _TARGET_LABEL_KEYS if target.get(key))
            if not parts and target.get("source_kind"):
                parts.append(str(target["source_kind"]))
    result = job.result if isinstance(job.result, dict) else {}
    if not parts and isinstance(job, ScanJob):
        labels = _scan_source_labels(job)
        parts.append(", ".join(labels[:3]) + (f" +{len(labels) - 3} more" if len(labels) > 3 else ""))
    if result.get("pushed") and not source:
        parts.insert(0, "push")
    return " / ".join(dict.fromkeys(part for part in parts if part))[:200] or "unlabelled scope"


def scope_label_basis(job: Any, label: str) -> str:
    """``default_scan_request`` when the label is only the unnamed-request fallback, not a named source or target."""
    if isinstance(job, ScanJob) and label == "local-agents" and _scan_source_labels(job) == ["local-agents"]:
        return "default_scan_request"
    return "scan_target"


def _snapshot_ref(job: Any) -> dict[str, str]:
    return {"scan_id": graph_scan_id(job), "job_id": str(job.job_id), "captured_at": scan_evidence_authority_key(job)[0]}


def _scope_id(scope: str) -> str:
    return hashlib.sha256(scope.encode()).hexdigest()[:16]


_ISSUE_CHANGE_KEYS = ("critical", "high", "medium", "low", "total")


def _recorded_issue_counts(tenant: str) -> dict[str, dict[str, Any]]:
    """Posture-basis issue counts each trended scan recorded, by scan id."""
    from agent_bom.api.stores import _get_trend_store

    try:
        history = _get_trend_store().get_history(limit=365, tenant_id=tenant)
    except Exception:  # broad-except: the issue overlay is optional and never fails the graph diff it annotates
        _logger.warning("Trend history unavailable for the change issue basis")
        return {}
    counts: dict[str, dict[str, Any]] = {}
    for point in history:
        recorded = point.comparison_metadata.get("issue_counts")
        if point.scan_id and isinstance(recorded, dict) and recorded.get("basis") == "issue_groups":
            counts[str(point.scan_id)] = recorded
    return counts


def _issue_change(recorded: dict[str, dict[str, Any]], old_id: str, new_id: str) -> dict[str, Any] | None:
    """The trend's open-issue counts for both scans of a pair; ``None`` unless both were recorded."""
    old, new = recorded.get(old_id), recorded.get(new_id)
    if old is None or new is None:
        return None
    return {
        "basis": "issue_groups",
        "old": {key: int(old.get(key) or 0) for key in _ISSUE_CHANGE_KEYS},
        "new": {key: int(new.get(key) or 0) for key in _ISSUE_CHANGE_KEYS},
    }


def _empty_totals() -> dict[str, Any]:
    zero = {"added": 0, "removed": 0, "changed": 0}
    return {"nodes": dict(zero), "edges": dict(zero), "changed_sources": 0, "unchanged_sources": 0, "new_sources": 0}


def _page_payload(store: Any, tenant: str, page: list[_Scope]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Diff each paired scope through the shared generation-keyed rows cache."""
    sources: list[dict[str, Any]] = []
    first: list[dict[str, Any]] = []
    totals = _empty_totals()
    unpaired = {graph_scan_id(scope.current) for scope in page if scope.previous is None}
    stats = {str(row.get("scan_id")): row for row in store.snapshots_by_ids(tenant_id=tenant, scan_ids=unpaired)} if unpaired else {}
    recorded = _recorded_issue_counts(tenant) if len(unpaired) < len(page) else {}
    for scope in page:
        label = scope_label(scope.current)
        base = {
            "scope_id": _scope_id(scope.key),
            "label": label,
            "label_basis": scope_label_basis(scope.current, label),
            "new": _snapshot_ref(scope.current),
        }
        if scope.previous is None:
            row = stats.get(graph_scan_id(scope.current), {})
            first.append(
                {
                    **base,
                    "reason": "first_observation" if not scope.skipped and not scope.searched_out else "previous_graph_unavailable",
                    "node_count": int(row.get("node_count") or 0),
                    "edge_count": int(row.get("edge_count") or 0),
                    "skipped_snapshots": scope.skipped,
                }
            )
            totals["new_sources"] += 1
            continue
        old_id, new_id = scope.previous.scan_id, graph_scan_id(scope.current)
        _diff, rows = _compute_rows(store, tenant, old_id, new_id)
        summary = diff_summary(rows)
        if summary["total_changes"]:
            summary["highlights"].update(_path_changes(store, tenant, old_id, new_id))
            _label_endpoints(store, tenant, old_id, new_id, summary["highlights"])
            attribute_highlight_vendors(store, tenant, old_id, new_id, summary["highlights"])
        for kind in ("nodes", "edges"):
            for change, count in summary["totals"][kind].items():
                totals[kind][change] += count
        totals["changed_sources" if summary["total_changes"] else "unchanged_sources"] += 1
        sources.append(
            {
                **base,
                "old": {"scan_id": scope.previous.scan_id, "job_id": scope.previous.job_id, "captured_at": scope.previous.captured_at},
                "baseline": scope.previous.basis,
                "counts": summary["totals"],
                "total_changes": summary["total_changes"],
                "nodes_by_entity_type": summary["nodes_by_entity_type"],
                "changes_by_source": changes_by_collected_source(store, tenant, old_id, new_id, rows),
                "highlights": summary["highlights"],
                "issue_change": _issue_change(recorded, old_id, new_id),
                "skipped_snapshots": scope.skipped,
            }
        )
    return sources, first, totals


async def graph_estate_changes_read(request: Request, *, limit: int = SOURCE_LIMIT_DEFAULT, offset: int = 0) -> dict[str, Any]:
    """Per-scope changes since each scope's previous snapshot, one bounded page of scopes."""
    if not 1 <= limit <= SOURCE_LIMIT_MAX:
        raise HTTPException(status_code=422, detail=f"limit must be between 1 and {SOURCE_LIMIT_MAX}")
    if offset < 0:
        raise HTTPException(status_code=422, detail="offset must be non-negative")
    tenant = _runtime._tenant(request)
    refuse_unpinned_read_while_seeding("", tenant)
    store = _runtime._get_graph_store_or_503()
    scopes, reasons = await _runtime._graph_store_call(_plan, store, _get_store(), tenant)
    page = scopes[offset : offset + limit]
    sources, first, totals = await _runtime._graph_store_call(_page_payload, store, tenant, page)
    has_more = offset + len(page) < len(scopes)
    return {
        "schema_version": "v1",
        "evidence_scope": "current_estate",
        "sources": sources,
        "new_sources": first,
        "totals": totals,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(page),
            "total": len(scopes),
            "has_more": has_more,
            "next_offset": offset + len(page) if has_more else None,
        },
        "completeness": graph_completeness(
            returned=len(page), total=len(scopes), truncated=has_more, reason="source_page_limit" if has_more else ""
        ),
        "completeness_reasons": sorted(reasons),
    }


__all__ = ["PREVIOUS_SEARCH_LIMIT", "SOURCE_LIMIT_DEFAULT", "SOURCE_LIMIT_MAX", "graph_estate_changes_read", "scope_label"]
