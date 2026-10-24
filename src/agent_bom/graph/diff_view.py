"""Bounded projections of a two-snapshot graph diff.

A store diff lists every added, removed and changed node and edge, which on a
large estate is megabytes. REST ``/v1/graph/diff`` and the MCP ``graph_diff``
tool answer from this module instead: a summary (counts per change kind by
entity type / relationship plus the most significant changes), a filtered page
of change rows in a stable order, or the legacy full shape under hard caps.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

DIFF_VIEWS = ("summary", "detail", "full")
CHANGE_KINDS = ("added", "removed", "changed")
ROW_KINDS = ("node", "edge")
DETAIL_MAX_LIMIT = 200
SUMMARY_TOP_N = 10
FULL_ROW_CAP = 5_000
FULL_BYTE_CAP = 2_000_000
# Node attribute blobs dominate the legacy payload; detail rows and /v1/graph/nodes carry them.
FULL_VIEW_OMITTED_FIELDS = ("attributes",)

FINDING_ENTITY_TYPES = frozenset({"vulnerability", "misconfiguration"})
CREDENTIAL_REACH_RELATIONSHIPS = frozenset({"exposes_cred", "reaches_tool", "shares_cred", "used_credential", "authenticates_as"})
CONTROL_ENTITY_TYPES = frozenset({"access_policy"})
CONTROL_RELATIONSHIPS = frozenset({"protects", "governs"})

_LEGACY_KEYS = {
    ("node", "added"): "nodes_added",
    ("node", "removed"): "nodes_removed",
    ("node", "changed"): "nodes_changed",
    ("edge", "added"): "edges_added",
    ("edge", "removed"): "edges_removed",
    ("edge", "changed"): "edges_changed",
}
_LEGACY_KIND = {"added": "new", "removed": "removed", "changed": "changed"}
_EDGE_FINGERPRINT = ("direction", "weight", "traversable", "confidence", "provenance", "evidence", "activity_id")


@dataclass(frozen=True, slots=True)
class DiffFilters:
    """Row filters; ``entity_type`` keeps node rows, ``relationship`` keeps edge rows."""

    change: str | None = None
    kind: str | None = None
    entity_type: str | None = None
    relationship: str | None = None
    node_id: str | None = None

    def active(self) -> dict[str, str]:
        values = {
            "change": self.change,
            "kind": self.kind,
            "entity_type": self.entity_type,
            "relationship": self.relationship,
            "node_id": self.node_id,
        }
        return {key: value for key, value in values.items() if value is not None}

    def matches(self, row: dict[str, Any]) -> bool:
        if self.change is not None and row["change"] != self.change:
            return False
        if self.kind is not None and row["kind"] != self.kind:
            return False
        if self.entity_type is not None and (row["kind"] != "node" or row.get("entity_type") != self.entity_type):
            return False
        if self.relationship is not None and (row["kind"] != "edge" or row.get("relationship") != self.relationship):
            return False
        if self.node_id is not None:
            ids = {row["id"]} if row["kind"] == "node" else {row.get("source"), row.get("target")}
            if self.node_id not in ids:
                return False
        return True


def validate_filters(filters: DiffFilters) -> str | None:
    """A message naming the first invalid filter, or ``None``."""
    if filters.change is not None and filters.change not in CHANGE_KINDS:
        return f"change must be one of: {', '.join(CHANGE_KINDS)}"
    if filters.kind is not None and filters.kind not in ROW_KINDS:
        return f"kind must be one of: {', '.join(ROW_KINDS)}"
    for name in ("entity_type", "relationship", "node_id"):
        value = getattr(filters, name)
        if value is not None and (not value.strip() or len(value) > 512 or "\x00" in value):
            return f"{name} is not a valid identifier"
    return None


def edge_parts(entry: Any) -> tuple[str, str, str, dict[str, Any] | None, dict[str, Any] | None]:
    """``(source, target, relationship, before, after)`` for any store edge entry shape."""
    if isinstance(entry, dict):
        before, after = entry.get("before"), entry.get("after")
        edge = after or before or entry
        source = str(edge.get("source_id") or edge.get("source") or "")
        target = str(edge.get("target_id") or edge.get("target") or "")
        return source, target, str(edge.get("relationship") or ""), before, after
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        return str(entry[0]), str(entry[1]), str(entry[2]), None, None
    return str(entry), "", "", None, None


def _node_id(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("id") or entry.get("node_id") or "")
    return str(entry)


def _node_row(
    change: str,
    entry: Any,
    *,
    types: dict[str, dict[str, Any]],
    deltas: dict[str, list[dict[str, Any]]],
    renamed: dict[str, str] | None = None,
) -> dict[str, Any]:
    nid = _node_id(entry)
    meta = entry if isinstance(entry, dict) else types.get(nid, {})
    row: dict[str, Any] = {
        "kind": "node",
        "change": change,
        "id": nid,
        "entity_type": str(meta.get("entity_type") or "") or None,
        "label": meta.get("label") or nid,
        "severity": meta.get("severity") or None,
        "risk_score": float(meta.get("risk_score") or 0.0),
    }
    if change == "changed" and renamed and nid in renamed:
        row["previous_id"] = renamed[nid]
    if change == "changed":
        row["deltas"] = [{"field": delta.get("field"), "summary": delta.get("summary")} for delta in deltas.get(nid, [])]
    return row


def _edge_row(change: str, entry: Any) -> dict[str, Any]:
    source, target, relationship, before, after = edge_parts(entry)
    row: dict[str, Any] = {
        "kind": "edge",
        "change": change,
        "id": f"{source}|{target}|{relationship}",
        "source": source,
        "target": target,
        "relationship": relationship,
    }
    if change == "changed" and before is not None and after is not None:
        row["changed_fields"] = [field for field in _EDGE_FINGERPRINT if before.get(field) != after.get(field)]
    return row


def diff_rows(diff: dict[str, Any], *, changed_node_meta: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Every change as one row, ordered nodes before edges, then change kind, then id."""
    types = changed_node_meta or {}
    deltas = diff.get("attribute_deltas") or {}
    renamed = diff.get("nodes_renamed") or {}
    rows: list[dict[str, Any]] = []
    for (kind, change), key in _LEGACY_KEYS.items():
        for entry in diff.get(key) or []:
            rows.append(
                _node_row(change, entry, types=types, deltas=deltas, renamed=renamed) if kind == "node" else _edge_row(change, entry)
            )
    order = {value: index for index, value in enumerate(CHANGE_KINDS)}
    rows.sort(key=lambda row: (row["kind"] != "node", order[row["change"]], row["id"]))
    return rows


def _empty_counts() -> dict[str, int]:
    return {change: 0 for change in CHANGE_KINDS}


def _top(rows: Iterable[dict[str, Any]], top_n: int) -> dict[str, Any]:
    selected = sorted(rows, key=lambda row: (-float(row.get("risk_score") or 0.0), row["id"]))
    return {"count": len(selected), "top": selected[:top_n]}


def diff_summary(rows: list[dict[str, Any]], *, top_n: int = SUMMARY_TOP_N) -> dict[str, Any]:
    """Counts per change kind by entity type and relationship plus the most significant changes."""
    totals = {"nodes": _empty_counts(), "edges": _empty_counts()}
    by_type: dict[str, dict[str, int]] = {}
    by_relationship: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["kind"] == "node":
            totals["nodes"][row["change"]] += 1
            by_type.setdefault(row.get("entity_type") or "unknown", _empty_counts())[row["change"]] += 1
        else:
            totals["edges"][row["change"]] += 1
            by_relationship.setdefault(row.get("relationship") or "unknown", _empty_counts())[row["change"]] += 1
    nodes = [row for row in rows if row["kind"] == "node"]
    edges = [row for row in rows if row["kind"] == "edge"]
    highlights = {
        "new_critical_findings": _top(
            (
                row
                for row in nodes
                if row["change"] == "added" and row.get("entity_type") in FINDING_ENTITY_TYPES and row.get("severity") == "critical"
            ),
            top_n,
        ),
        "new_credential_reach": _top(
            (row for row in edges if row["change"] == "added" and row.get("relationship") in CREDENTIAL_REACH_RELATIONSHIPS), top_n
        ),
        "removed_controls": _top(
            (
                row
                for row in rows
                if row["change"] == "removed"
                and (row.get("entity_type") in CONTROL_ENTITY_TYPES or row.get("relationship") in CONTROL_RELATIONSHIPS)
            ),
            top_n,
        ),
    }
    return {
        "totals": totals,
        "total_changes": len(rows),
        "nodes_by_entity_type": dict(sorted(by_type.items())),
        "edges_by_relationship": dict(sorted(by_relationship.items())),
        "highlights": highlights,
    }


def _path_key(path: Any) -> tuple[str, ...]:
    return tuple(str(hop) for hop in (getattr(path, "hops", None) or [getattr(path, "source", ""), getattr(path, "target", "")]))


def new_attack_paths(
    old_paths: list[Any], new_paths: list[Any], *, old_total: int, new_total: int, window: int, top_n: int = SUMMARY_TOP_N
) -> dict[str, Any]:
    """Stored paths present in the new snapshot and absent from the old one."""
    if not old_total and not new_total:
        return {"status": "not_materialized", "count": 0, "top": []}
    old_keys = {_path_key(path) for path in old_paths}
    added = [path for path in new_paths if _path_key(path) not in old_keys]
    added.sort(key=lambda path: (-float(getattr(path, "composite_risk", 0.0) or 0.0), _path_key(path)))
    complete = old_total <= window and new_total <= window
    return {
        "status": "complete" if complete else "lower_bound",
        "count": len(added),
        "count_is_lower_bound": not complete,
        "top": [
            {
                "source": path.source,
                "target": path.target,
                "hops": list(path.hops),
                "composite_risk": float(path.composite_risk or 0.0),
                "summary": getattr(path, "summary", "") or "",
            }
            for path in added[:top_n]
        ],
    }


def cursor_scope(tenant_id: str, old: str, new: str, filters: DiffFilters) -> str:
    return hashlib.sha256(json.dumps([tenant_id, old, new, sorted(filters.active().items())]).encode()).hexdigest()


def encode_cursor(scope: str, revision: str, offset: int) -> str:
    raw = json.dumps({"v": 1, "scope": scope, "revision": revision, "offset": offset}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str, scope: str) -> dict[str, Any]:
    """The cursor payload; ``ValueError`` when it is malformed or from another query."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("malformed cursor") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1 or payload.get("scope") != scope:
        raise ValueError("cursor does not belong to this query")
    if not isinstance(payload.get("offset"), int) or payload["offset"] < 0 or not isinstance(payload.get("revision"), str):
        raise ValueError("cursor does not belong to this query")
    return payload


def detail_page(rows: list[dict[str, Any]], *, offset: int, limit: int) -> tuple[list[dict[str, Any]], bool]:
    page = rows[offset : offset + limit]
    return page, offset + len(page) < len(rows)


def full_view(
    diff: dict[str, Any], rows: list[dict[str, Any]], *, row_cap: int = FULL_ROW_CAP, byte_cap: int = FULL_BYTE_CAP
) -> dict[str, Any]:
    """The legacy list shape, cut at ``row_cap`` rows and ``byte_cap`` bytes, nodes first."""
    budget = min(row_cap, len(rows))
    while True:
        payload = _legacy_lists(diff, rows[:budget])
        size = len(json.dumps(payload, separators=(",", ":"), default=str))
        if size <= byte_cap or budget == 0:
            break
        budget = budget * 3 // 4
    truncated = budget < len(rows)
    payload["truncated"] = truncated
    payload["complete"] = not truncated
    payload["returned_changes"] = budget
    payload["total_changes"] = len(rows)
    payload["limits"] = {"row_cap": row_cap, "byte_cap": byte_cap}
    payload["omitted_fields"] = list(FULL_VIEW_OMITTED_FIELDS)
    return payload


def _legacy_lists(diff: dict[str, Any], kept: list[dict[str, Any]]) -> dict[str, Any]:
    wanted: dict[str, set[str]] = {key: set() for key in _LEGACY_KEYS.values()}
    for row in kept:
        wanted[_LEGACY_KEYS[(row["kind"], row["change"])]].add(row["id"])
    payload: dict[str, Any] = {}
    node_index: dict[str, str] = {}
    edge_index: dict[str, str] = {}
    for (kind, change), key in _LEGACY_KEYS.items():
        entries = []
        for entry in diff.get(key) or []:
            if kind == "node":
                entry_id = _node_id(entry)
            else:
                source, target, relationship, _before, _after = edge_parts(entry)
                entry_id = f"{source}|{target}|{relationship}"
            if entry_id not in wanted[key]:
                continue
            if isinstance(entry, dict):
                entry = {key: value for key, value in entry.items() if key not in FULL_VIEW_OMITTED_FIELDS}
                entry["change_kind"] = entry.get("change_kind") or _LEGACY_KIND[change]
            entries.append(entry)
            (node_index if kind == "node" else edge_index)[entry_id] = _LEGACY_KIND[change]
        payload[key] = entries
    kept_nodes = set(node_index)
    payload["attribute_deltas"] = {nid: deltas for nid, deltas in (diff.get("attribute_deltas") or {}).items() if nid in kept_nodes}
    payload["change_kind_index"] = {"nodes": node_index, "edges": edge_index}
    return payload


__all__ = [
    "CHANGE_KINDS",
    "DETAIL_MAX_LIMIT",
    "DIFF_VIEWS",
    "FULL_BYTE_CAP",
    "FULL_ROW_CAP",
    "FULL_VIEW_OMITTED_FIELDS",
    "ROW_KINDS",
    "SUMMARY_TOP_N",
    "DiffFilters",
    "cursor_scope",
    "decode_cursor",
    "detail_page",
    "diff_rows",
    "diff_summary",
    "edge_parts",
    "encode_cursor",
    "full_view",
    "new_attack_paths",
    "validate_filters",
]
