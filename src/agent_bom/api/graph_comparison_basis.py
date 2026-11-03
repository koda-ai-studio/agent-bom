"""Conservative comparison bases for the graph's scoped change strip."""

from collections.abc import Mapping
from typing import Any

from agent_bom.api.trend_comparison import comparison_metadata


def graph_collection_basis(result: Any) -> dict[str, Any]:
    """Reuse the trend coverage contract without materialising finding observations."""
    result = result if isinstance(result, Mapping) else {}
    fields = {key: result.get(key) for key in ("scan_run", "coverage_warnings", "scan_sources")}
    metadata = comparison_metadata({**fields, "findings": []}, None)
    return {key: metadata[key] for key in ("collection_coverage", "coverage_key")}


def graph_comparison_basis(old: Mapping[str, Any] | None, new: Mapping[str, Any], baseline: str) -> dict[str, str | None]:
    reason = None
    if baseline != "scope_history" or old is None:
        reason = "scope_history_unavailable"
    elif old.get("collection_coverage") != "complete" or new.get("collection_coverage") != "complete":
        reason = "incomplete_collection"
    elif old.get("coverage_key") != new.get("coverage_key"):
        reason = "different_collection_coverage"
    return {"status": "unavailable" if reason else "comparable", "reason": reason}


def recorded_kev_change(recorded: Mapping[str, dict[str, Any]], old_id: str, new_id: str) -> dict[str, Any] | None:
    """Only same-scope, same-measurement, complete trend points support a KEV delta."""
    old, new = recorded.get(old_id, {}), recorded.get(new_id, {})
    a, b = old.get("trend_basis", {}), new.get("trend_basis", {})
    if any(not a.get(key) or a.get(key) != b.get(key) for key in ("scope_id", "measurement_version", "coverage_key")):
        return None
    if a.get("collection_coverage") != "complete" or b.get("collection_coverage") != "complete":
        return None
    before, after = old.get("kev_count"), new.get("kev_count")
    if type(before) is not int or type(after) is not int or before < 0 or after < 0:
        return None
    return {"basis": "issue_groups", "old": before, "new": after, "delta": after - before}
