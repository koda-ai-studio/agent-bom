"""REST/MCP adapters over :mod:`agent_bom.graph.node_alias_resolution`."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.node_alias_resolution import resolve_snapshot_node_id as resolve_snapshot_node_id
from agent_bom.graph.node_alias_resolution import resolve_snapshot_node_ids


def resolve_assessment_node_ids(store: Any, body: Any, *, tenant_id: str, scan_id: str) -> Any:
    """Copy of an assessment request whose ``root_node_id`` / ``affected_node_id`` are canonical in ``scan_id``."""
    given = [value for value in (body.root_node_id, getattr(body, "affected_node_id", None)) if value]
    _ordered, mapping = resolve_snapshot_node_ids(store, tenant_id=tenant_id, scan_id=scan_id, node_ids=given)
    if not mapping:
        return body
    update = {"root_node_id": mapping.get(body.root_node_id, body.root_node_id)}
    if getattr(body, "affected_node_id", None):
        update["affected_node_id"] = mapping.get(body.affected_node_id, body.affected_node_id)
    return body.model_copy(update=update)


def resolve_scenario_aliases(graph_store: Any, tenant_id: str, scan_id: str, scenario: dict[str, Any]) -> dict[str, Any]:
    """Point operations recorded against ids the base snapshot replaced at its canonical nodes."""
    operations = [dict(op) for op in scenario.get("operations") or [] if isinstance(op, dict)]
    fields = ("node_id", "source", "target")
    refs = [str(op[f]) for op in operations for f in fields if isinstance(op.get(f), str) and not str(op[f]).startswith("proposal:")]
    _ordered, mapping = resolve_snapshot_node_ids(graph_store, tenant_id=tenant_id, scan_id=scan_id, node_ids=list(dict.fromkeys(refs)))
    if not mapping:
        return scenario
    for op in operations:
        for f in fields:
            if isinstance(op.get(f), str) and op[f] in mapping:
                op[f] = mapping[op[f]]
    return {**scenario, "operations": operations}
