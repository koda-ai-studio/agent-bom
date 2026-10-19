"""Finding view filters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, NamedTuple

from agent_bom.api.finding_list_envelope import finding_list_envelope
from agent_bom.api.finding_row_shapes import _package_base_name, _row_vuln_id

_FINDINGS_VIEW_FILTER_MAX_ROWS = 50_000


def _finding_triage_state(
    row: dict[str, Any],
    triage_index: Any,
) -> dict[str, Any] | None:
    """Project the newest active triage state onto one occurrence row."""
    from agent_bom.api.routes.enterprise import triage_state_for

    raw_servers = row.get("affected_servers")
    servers = [str(row.get("server_name") or "")]
    if isinstance(raw_servers, list):
        servers.extend(str(value) for value in raw_servers if str(value).strip())
    for server_name in dict.fromkeys(servers):
        state = triage_state_for(
            triage_index,
            vuln_id=_row_vuln_id(row),
            package=_package_base_name(row),
            server_name=server_name,
        )
        if state is not None:
            return state
    return None


def _matches_reachability(reachable: Any, requested: str | None) -> bool:
    return (
        requested is None
        or (requested == "reachable" and reachable is True)
        or (requested == "unreachable" and reachable is False)
        or (requested == "unassessed" and reachable is None)
    )


def _view_filtered_row(
    source_row: dict[str, Any],
    *,
    triage_index: Any,
    reachability: str | None,
    triage: str | None,
    suppressed_only: bool,
) -> dict[str, Any] | None:
    """Annotate one occurrence with triage state; return it only when it matches."""
    row = dict(source_row)
    triage_state = _finding_triage_state(row, triage_index) if triage_index is not None else None
    if triage_index is not None:
        row["triage_id"] = triage_state.get("id") if triage_state else None
        row["triage_decision"] = triage_state.get("decision") if triage_state else None
        row["triage_queue_state"] = triage_state.get("queue_state") if triage_state else None
    decision = triage_state.get("decision") if triage_state else None
    triage_matches = triage is None or decision == triage or (triage == "untriaged" and decision is None)
    if not (_matches_reachability(row.get("graph_reachable"), reachability) and triage_matches):
        return None
    if suppressed_only and row.get("suppressed") is not True:
        return None
    return row


class _ViewWalk(NamedTuple):
    matches: list[dict[str, Any]]
    first_page: dict[str, Any] | None
    warnings: list[str]
    next_cursor: str | None
    exhausted: bool
    truncated: bool
    total_matches: int | None = None


def _walk_view_filtered_findings(
    fetch_page: Callable[[int, str | None], dict[str, Any]],
    row_filter: Callable[[dict[str, Any]], dict[str, Any] | None],
    *,
    target: int,
    cursor: str | None,
) -> _ViewWalk:
    """Walk the canonical keyset stream until ``target`` rows match or the budget is spent."""
    source_cursor = cursor
    rows_seen = 0
    matches: list[dict[str, Any]] = []
    first_page: dict[str, Any] | None = None
    warnings: list[str] = []
    exhausted = False
    while rows_seen < _FINDINGS_VIEW_FILTER_MAX_ROWS and len(matches) < target:
        page_limit = min(1000, _FINDINGS_VIEW_FILTER_MAX_ROWS - rows_seen, max(1, target - len(matches)))
        page = fetch_page(page_limit, source_cursor)
        if first_page is None:
            first_page = page
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        raw_rows = page.get("findings")
        page_rows = [row for row in raw_rows if isinstance(row, dict)] if isinstance(raw_rows, list) else []
        rows_seen += len(page_rows)
        matches.extend(row for row in map(row_filter, page_rows) if row is not None)
        source_cursor = str(page.get("next_cursor") or "") or None
        if not source_cursor:
            exhausted = True
            break
    truncated = not exhausted and rows_seen >= _FINDINGS_VIEW_FILTER_MAX_ROWS
    total_matches = len(matches) if exhausted else None
    if not exhausted and not truncated and cursor is None:
        # Count (without retaining) the rest of the stream so the first page
        # reports an exact total; the walk budget still bounds the work.
        counted, count_cursor = len(matches), source_cursor
        while count_cursor and rows_seen < _FINDINGS_VIEW_FILTER_MAX_ROWS:
            page = fetch_page(min(1000, _FINDINGS_VIEW_FILTER_MAX_ROWS - rows_seen), count_cursor)
            raw_rows = page.get("findings")
            page_rows = [row for row in raw_rows if isinstance(row, dict)] if isinstance(raw_rows, list) else []
            rows_seen += len(page_rows)
            counted += sum(1 for row in map(row_filter, page_rows) if row is not None)
            count_cursor = str(page.get("next_cursor") or "") or None
        total_matches = counted if count_cursor is None else None
        truncated = count_cursor is not None
    if truncated:
        warnings.append(f"Finding view filters inspected {_FINDINGS_VIEW_FILTER_MAX_ROWS} rows; additional occurrences remain.")
    return _ViewWalk(matches, first_page, warnings, source_cursor, exhausted, truncated, total_matches)


def _copy_first_page_metadata(envelope: dict[str, Any], first_page: dict[str, Any] | None, keys: tuple[str, ...]) -> None:
    if not first_page:
        return
    if "window" in first_page:
        envelope["window"] = first_page["window"]
        envelope["count_metadata"]["window"] = first_page["window"]
    for key in keys:
        if key in first_page:
            envelope[key] = first_page[key]


def _view_filters(
    first_page: dict[str, Any] | None, *, suppressed_only: bool, reachability: str | None, triage: str | None
) -> dict[str, Any]:
    filters = dict(first_page.get("filters") or {}) if first_page else {}
    if suppressed_only:
        filters["status"] = "suppressed"
    if reachability is not None:
        filters["reachability"] = reachability
    if triage is not None:
        filters["triage"] = triage
    return filters


def _view_envelope(
    walk: _ViewWalk, *, limit: int, offset: int, cursor: str | None, sort: str, scan_id: str | None, filters: dict[str, Any]
) -> dict[str, Any]:
    total = walk.total_matches if cursor is None else None
    envelope = finding_list_envelope(
        findings=walk.matches[:limit] if cursor else walk.matches[offset : offset + limit],
        total=total,
        limit=limit,
        offset=0 if cursor else offset,
        sort=sort,
        scan_id=scan_id,
        cursor=cursor or "",
        next_cursor=walk.next_cursor or "",
        filters=filters,
        warnings=list(dict.fromkeys(walk.warnings)),
        total_approximate=total is None,
        source="scan_and_current_ingest_findings",
        scope="tenant current-state findings with graph and triage view filters",
    )
    _copy_first_page_metadata(envelope, walk.first_page, ("scope_completeness",))
    return envelope
