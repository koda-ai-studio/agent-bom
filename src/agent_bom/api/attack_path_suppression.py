"""Attack paths through the one suppression source the findings list applies.

A path carries the finding occurrences it ends on (``finding_ids``). When an
approved exception suppresses every one of them the path is not an open path:
it stays in the queue as evidence, marked ``suppressed``, and the queue reports
how many of its paths are suppressed so open-path counts exclude them. A path
with any open occurrence, or with no recorded occurrence, stays open.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Iterable
from typing import Any

SUPPRESSION_BASIS = "approved_exception"
_COUNT_CACHE_MAX = 64
_COUNT_CACHE: OrderedDict[tuple[str, ...], tuple[int, bool]] = OrderedDict()
_COUNT_LOCK = threading.Lock()


def count_cache_key(tenant: str, scan_id: str, generation: str, filters: dict[str, Any], suppressed: frozenset[str]) -> tuple[str, ...]:
    """A suppressed-path count is fixed by the snapshot generation, the queue filters and the suppressed set."""
    digest = hashlib.sha256("\n".join(sorted(suppressed)).encode()).hexdigest()
    return (tenant, scan_id, generation, repr(sorted(filters.items())), digest)


def cached_count(key: tuple[str, ...]) -> tuple[int, bool] | None:
    with _COUNT_LOCK:
        hit = _COUNT_CACHE.get(key)
        if hit is not None:
            _COUNT_CACHE.move_to_end(key)
        return hit


def remember_count(key: tuple[str, ...], value: tuple[int, bool]) -> None:
    with _COUNT_LOCK:
        _COUNT_CACHE[key] = value
        _COUNT_CACHE.move_to_end(key)
        while len(_COUNT_CACHE) > _COUNT_CACHE_MAX:
            _COUNT_CACHE.popitem(last=False)


def path_suppressed(finding_ids: Iterable[str] | None, suppressed: frozenset[str]) -> bool:
    ids = {str(fid) for fid in finding_ids or () if fid}
    return bool(ids) and ids <= suppressed


def mark_suppressed_paths(rows: list[dict[str, Any]], suppressed: frozenset[str]) -> int:
    """Stamp each serialized path; return how many on this page are suppressed."""
    count = 0
    for row in rows:
        row["suppressed"] = path_suppressed(row.get("finding_ids"), suppressed)
        count += row["suppressed"]
    return count


def count_suppressed(paths: Iterable[Any], suppressed: frozenset[str]) -> int:
    return sum(1 for path in paths if path_suppressed(getattr(path, "finding_ids", None), suppressed))


def suppression_count_metadata(count: int | None, suppressed: frozenset[str], *, total: int, complete: bool) -> dict[str, Any]:
    """Suppressed and open path totals over the matching queue; ``count`` ``None`` when not enumerated."""
    if not suppressed:
        return {"suppressed_paths": 0, "open_paths": total, "suppression_basis": SUPPRESSION_BASIS, "suppression_complete": True}
    if count is None:
        return {"suppressed_paths": None, "open_paths": None, "suppression_basis": SUPPRESSION_BASIS, "suppression_complete": False}
    return {
        "suppressed_paths": count,
        "open_paths": total - count,
        "suppression_basis": SUPPRESSION_BASIS,
        "suppression_complete": complete,
    }


__all__ = [
    "SUPPRESSION_BASIS",
    "cached_count",
    "count_cache_key",
    "count_suppressed",
    "mark_suppressed_paths",
    "path_suppressed",
    "remember_count",
    "suppression_count_metadata",
]
