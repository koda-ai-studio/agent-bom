"""Remediation targets the matched advisory window does not carry itself."""

from __future__ import annotations

import sqlite3
from typing import Callable, Optional

# Re-exported for the lookup path; defined on the leaf module so scanners and
# evidence code can name them without importing the database package.
from agent_bom.advisory_ids import LEGACY_RECEIPT_WARNING as LEGACY_RECEIPT_WARNING
from agent_bom.advisory_ids import UNVERIFIED_RANGE_WARNING as UNVERIFIED_RANGE_WARNING
from agent_bom.core.versions.osv import is_valid_fix_version
from agent_bom.version_utils import compare_version_order


def next_window_fix(
    row: sqlite3.Row,
    rows: list[sqlite3.Row],
    version: str,
    match_state: Callable[..., str],
    comparator_ecosystem: Callable[[str], str],
) -> Optional[str]:
    """Earliest fix another window of the same advisory names, when this window has none.

    Mirrors :func:`agent_bom.scanners.osv._next_unaffected_fixes`: a release line
    ended by ``last_affected`` can be remediated by a later line's fix, as long as
    no window of that advisory still marks the fix affected (or unknown).
    """

    windows = [
        other
        for other in rows
        if other["id"] == row["id"] and other["ecosystem"] == row["ecosystem"] and other["package_name"] == row["package_name"]
    ]

    def state(candidate: str) -> str:
        states = {
            match_state(candidate, w["introduced"], w["fixed"], w["last_affected"], w["ecosystem"], w["limit_version"]) for w in windows
        }
        return "affected" if "affected" in states else "unknown" if "unknown" in states else "unaffected"

    eco = comparator_ecosystem(row["ecosystem"])
    best: Optional[str] = None
    for window in windows:
        fix = (window["fixed"] or "").strip()
        if not fix or not is_valid_fix_version(fix):
            continue
        order = compare_version_order(fix, version, eco)
        if order is None or order <= 0 or state(fix) != "unaffected":
            continue
        if best is None or (compare_version_order(fix, best, eco) or 0) < 0:
            best = fix
    return best
