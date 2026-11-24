"""Per-row signal filters on the findings queue: known exploitation and fix availability.

Shared by the in-memory scan rows and the hub store's scoped walk through
:func:`agent_bom.finding_scope.row_matches_scope`, so the two cannot diverge.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def row_has_fix(row: Mapping[str, Any]) -> bool:
    """Whether a finding records a version that fixes it: ``fixed_version`` or any ``remediation_versions`` entry."""
    versions = row.get("remediation_versions")
    has_remediation_version = isinstance(versions, (list, tuple)) and any(str(value).strip() for value in versions)
    return bool(str(row.get("fixed_version") or "").strip()) or has_remediation_version


def row_matches_signal_filters(row: Mapping[str, Any], filters: Mapping[str, str]) -> bool:
    """``kev`` and ``fix`` filters; an absent filter matches every row."""
    # KEV leads the executive headline, "actively exploited, fix these first", so the list must answer it.
    # An absent verdict is not a match: a row nobody checked is never presented as known-exploited.
    wanted_kev = filters.get("kev")
    if wanted_kev is not None and (row.get("is_kev") is True) is not (str(wanted_kev).strip().lower() in {"true", "1", "yes"}):
        return False
    # Fix availability splits the queue into "upgrade" and "mitigate".
    wanted_fix = filters.get("fix")
    return wanted_fix not in ("available", "none") or row_has_fix(row) is (wanted_fix == "available")
