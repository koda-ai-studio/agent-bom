"""Finding grouping."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import HTTPException

from agent_bom.api import finding_cursor
from agent_bom.api.finding_list_envelope import finding_list_envelope
from agent_bom.api.finding_list_helpers import _FINDING_GROUP_MAX_OCCURRENCES, _FINDING_GROUP_OCCURRENCE_SAMPLE, _normalize_facet_severity
from agent_bom.api.finding_row_shapes import _package_identity, _row_vuln_id
from agent_bom.api.finding_scope_filters import _finding_identity as _finding_identity
from agent_bom.api.finding_view_filters import _copy_first_page_metadata as _copy_first_page_metadata
from agent_bom.canonical_ids import canonical_id
from agent_bom.evidence.finding_lanes import finding_lane, lane_counts


def _finding_group_offset(cursor: str | None, offset: int, sort_key: str) -> int:
    if not cursor:
        return offset
    try:
        group_offset = finding_cursor.decode_finding_group_cursor(cursor, expected_sort=sort_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid grouped findings cursor") from exc
    if group_offset is None:
        raise HTTPException(status_code=400, detail="Cursor is not valid for grouped findings")
    return group_offset


def _collect_group_occurrences(
    fetch_page: Callable[[int, str | None, bool], dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, list[str], str | None]:
    """Read the hard-bounded occurrence window in keyset-backed batches.

    Grouping already materializes at most 50k occurrences; small internal
    pages made the scan spine deserialize and enrich again for every page.
    """
    rows: list[dict[str, Any]] = []
    source_cursor: str | None = None
    first_page: dict[str, Any] | None = None
    warnings: list[str] = []
    while len(rows) < _FINDING_GROUP_MAX_OCCURRENCES:
        page = fetch_page(_FINDING_GROUP_MAX_OCCURRENCES - len(rows), source_cursor, first_page is None)
        if first_page is None:
            first_page = page
        page_rows = page.get("findings")
        if isinstance(page_rows, list):
            rows.extend(row for row in page_rows if isinstance(row, dict))
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        source_cursor = str(page.get("next_cursor") or "") or None
        if not source_cursor:
            break
    return rows, first_page, warnings, source_cursor


def _group_occurrence_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold occurrences onto their canonical issue identity with a bounded sample."""
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        group_id, group_key = _finding_group_identity(row)
        group = grouped.get(group_id)
        if group is None:
            group = dict(row)
            group.update(
                finding_group_id=group_id,
                finding_group_key=group_key,
                occurrence_count=0,
                unreconfirmed_occurrence_count=0,
                _occurrence_rows=[],
                occurrences_truncated=False,
            )
            grouped[group_id] = group
        group["occurrence_count"] = int(group["occurrence_count"]) + 1
        if row.get("observation_status") == "unreconfirmed":
            group["unreconfirmed_occurrence_count"] = int(group["unreconfirmed_occurrence_count"]) + 1
        occurrences = group["_occurrence_rows"]
        if isinstance(occurrences, list) and len(occurrences) < _FINDING_GROUP_OCCURRENCE_SAMPLE:
            occurrences.append(row)
        else:
            group["occurrences_truncated"] = True
    return list(grouped.values())


def _grouped_severity_counts(groups: list[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
    for group in groups:
        counts[_normalize_facet_severity(group.get("severity"))] += 1
    return counts


def _attach_grouping_metadata(
    envelope: dict[str, Any],
    *,
    first_page: dict[str, Any] | None,
    groups: list[dict[str, Any]],
    scanned: int,
    truncated: bool,
    severity_counts: dict[str, int] | None,
) -> None:
    envelope["grouping"] = {
        "status": "partial" if truncated else "complete",
        "scanned_occurrences": scanned,
        "scan_budget": _FINDING_GROUP_MAX_OCCURRENCES,
        "occurrence_total": sum(int(group.get("occurrence_count") or 0) for group in groups),
        "occurrence_sample_limit": _FINDING_GROUP_OCCURRENCE_SAMPLE,
    }
    _copy_first_page_metadata(envelope, first_page, ("facets", "facets_approximate", "facet_metadata", "scope_completeness"))
    if first_page and severity_counts is not None:
        envelope.setdefault("facets", {})["severity"] = severity_counts
        envelope["facet_metadata"]["severity_basis"] = "canonical issue groups"


def _groups_envelope(
    page_groups: list[dict[str, Any]],
    *,
    first_page: dict[str, Any] | None,
    total: int,
    limit: int,
    offset: int,
    sort: str,
    scan_id: str | None,
    cursor: str | None,
    next_cursor: str,
    warnings: list[str],
    severity: str | None,
    truncated: bool,
) -> dict[str, Any]:
    filters = dict(first_page.get("filters") or {}) if first_page else {}
    filters["group_occurrences"] = True
    if severity is not None:
        filters["severity"] = severity
    return finding_list_envelope(
        findings=page_groups,
        total=total,
        limit=limit,
        offset=offset,
        sort=sort,
        scan_id=scan_id,
        cursor=cursor or "",
        next_cursor=next_cursor,
        filters=filters,
        warnings=list(dict.fromkeys(warnings)),
        total_approximate=truncated,
        source="scan_and_current_ingest_finding_groups",
        scope="tenant current-state issue groups over asset-scoped occurrences",
    )


def _finding_group_identity(row: dict[str, Any]) -> tuple[str, str]:
    """Return the canonical aggregate identity without changing occurrence IDs."""
    supplied_id = str(row.get("finding_group_id") or "").strip()
    supplied_key = str(row.get("finding_group_key") or "").strip()
    vulnerability_id = _row_vuln_id(row).lower()
    if vulnerability_id:
        package, _, ecosystem = _package_identity(row)
        group_key = f"vulnerability:{vulnerability_id}:{ecosystem or 'unknown'}:{package}"
    else:
        evidence = row.get("evidence") or {}
        control = evidence.get("check_id") if isinstance(evidence, dict) else None
        if finding_lane(row) == "cloud" and row.get("provider") and control and control != "unknown":
            group_key = "cloud:" + ":".join(
                str(value or "unknown")
                for value in (row.get("provider"), row.get("finding_type"), evidence.get("benchmark_version"), control)
            )
        else:
            group_key = f"occurrence:{_finding_identity(row)}"
    # Persisted metadata is an optimization, not authority. A row can be
    # reclassified/enriched after ingest; stale group metadata must not collapse
    # two distinct advisories. Reuse it only when its semantic key still agrees.
    if supplied_id and supplied_key == group_key:
        return supplied_id, group_key
    return canonical_id("finding-group", group_key), group_key


def select_group_lane(all_groups: list[dict[str, Any]], severity: str | None, lane: str | None) -> tuple[list, list, dict]:
    severity_groups = [g for g in all_groups if severity is None or _normalize_facet_severity(g.get("severity")) == severity]
    counts = lane_counts(severity_groups)
    selected = lane.strip().lower() if lane and lane.strip() else None

    def matches(group: dict[str, Any]) -> bool:
        return selected is None or finding_lane(group) == selected

    return list(filter(matches, severity_groups)), list(filter(matches, all_groups)), counts


def attach_lane_counts(envelope: dict, lane: str | None, counts: dict, partial: bool, include: bool) -> None:
    if lane and lane.strip():
        envelope["filters"]["lane"] = lane.strip().lower()
    if include:
        envelope.setdefault("facets", {})["lane"] = counts
        envelope["lane_counts_approximate"] = partial
