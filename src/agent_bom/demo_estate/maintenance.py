"""Cheap checks before repeating the expensive demo composition."""

from typing import Any


def current_seed_summary(previous: dict[str, Any], *, usable_job: bool, snapshots_current: bool) -> dict[str, Any] | None:
    if not previous.get("enterprise_contract") or any(value for key, value in previous.items() if key.endswith("_error")):
        return None
    if not usable_job or not snapshots_current:
        return None
    return {**previous, "seeded": False, "graph_seeded": False, "reason": "demo_jobs_present", "rebuild_skipped": True}
