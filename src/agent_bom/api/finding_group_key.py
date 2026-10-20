"""The issue-group identity shared by the findings view and compliance controls."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_row_shapes import _package_identity, _row_vuln_id
from agent_bom.api.finding_scope_filters import _finding_identity
from agent_bom.canonical_ids import canonical_id
from agent_bom.evidence.finding_lanes import finding_lane


def _finding_group_identity(row: dict[str, Any], *, cloud_controls: bool = False) -> tuple[str, str]:
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
        if cloud_controls and finding_lane(row) == "cloud" and row.get("provider") and control and control != "unknown":
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
