"""Indexed cross-vendor reads over the stored attack-path rows.

Each materialized path row stores the vendor recorded on its own source and
target nodes (``source_vendor`` / ``target_vendor``). A row is cross-vendor
when both are set and differ, exactly as ``path_vendor_pair`` classifies a
path, so a page and its vendor-pair facets are two indexed queries instead of
reading and classifying the whole queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_bom.graph.container import AttackPath

CROSSING_SQL = " AND source_vendor <> '' AND target_vendor <> '' AND source_vendor <> target_vendor"


@dataclass(slots=True)
class StoredCrossVendorPage:
    scan_id: str
    created_at: str
    paths: list[AttackPath]
    total: int
    snapshot_total: int
    pairs: list[tuple[str, str, int]] = field(default_factory=list)


def vendor_filter_sql(*, placeholder: str, source_vendor: str | None, target_vendor: str | None) -> tuple[str, list[str]]:
    """The crossing predicate plus optional vendor equality, mirroring ``path_vendor_pair``."""
    clauses, params = CROSSING_SQL, []
    if source_vendor:
        clauses += f" AND source_vendor = {placeholder}"
        params.append(source_vendor)
    if target_vendor:
        clauses += f" AND target_vendor = {placeholder}"
        params.append(target_vendor)
    return clauses, params


def ordered_pairs(rows: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    """Most paths first, then by vendor names, as ``vendor_pair_facets`` orders them."""
    return sorted(((str(s), str(t), int(n)) for s, t, n in rows), key=lambda item: (-item[2], item[0], item[1]))


__all__ = ["CROSSING_SQL", "StoredCrossVendorPage", "ordered_pairs", "vendor_filter_sql"]
