"""Attack paths carrying the finding occurrences mapped to one compliance control.

A control's evidence is its mapped finding set. The finding store keys those
occurrences by id while paths record advisories, so an occurrence matches a
path that carries its id, or that carries its advisory through its own node.
The finding set is read for the request tenant only, through the same
canonical stream as ``GET /v1/findings?framework=&control=``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import Request

CONTROL_FOCUS_MAX_FINDINGS = 5_000


@dataclass(slots=True)
class ControlOccurrences:
    finding_ids: set[str] = field(default_factory=set)
    nodes_by_advisory: dict[str, set[str]] = field(default_factory=dict)
    count: int = 0
    complete: bool = True

    def add(self, row: dict[str, Any]) -> None:
        self.count += 1
        finding_id = str(row.get("finding_id") or row.get("id") or "").strip().lower()
        if finding_id:
            self.finding_ids.add(finding_id)
        advisory = str(row.get("cve_id") or row.get("vulnerability_id") or "").strip().lower()
        node_id = str(row.get("node_id") or "").strip()
        if advisory and node_id:
            self.nodes_by_advisory.setdefault(advisory, set()).add(node_id)

    def matches(self, path: Any) -> bool:
        recorded = [str(value).lower() for value in (*path.finding_ids, *path.vuln_ids)]
        if any(value in self.finding_ids for value in recorded):
            return True
        hops = set(path.hops)
        advisories = {*recorded, *(hop.split(":", 1)[1].lower() for hop in path.hops if hop.startswith("vuln:"))}
        return any(hops & self.nodes_by_advisory.get(advisory, set()) for advisory in advisories)


def _project(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in ("finding_id", "id", "cve_id", "vulnerability_id", "node_id")}


def control_occurrences(request: Request, *, framework: str, control: str, scan_id: str | None) -> ControlOccurrences:
    """The tenant's current finding occurrences mapped to ``framework``/``control``."""
    from agent_bom.api.routes.scan import current_findings_snapshot

    finding_scan = None if not scan_id or scan_id.startswith("current-estate:") else scan_id
    snapshot = current_findings_snapshot(
        request,
        max_findings=CONTROL_FOCUS_MAX_FINDINGS,
        framework=framework,
        control=control,
        scan_id=finding_scan,
        # Only identity is needed; projecting graph reachability onto every row costs seconds.
        project_graph_reachability=False,
        row_projection=_project,
    )
    occurrences = ControlOccurrences()
    for row in snapshot.get("findings", []):
        if isinstance(row, dict):
            occurrences.add(row)
    occurrences.complete = (snapshot.get("completeness") or {}).get("status") != "partial"
    return occurrences
