"""One generation-pinned consequence service for HTTP and MCP."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import Field, field_validator

from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.graph.consequence.contracts import ConsequenceAssessment, ConsequenceRequest
from agent_bom.graph.consequence.service import assess_consequences


class GraphConsequenceRequest(ConsequenceRequest):
    scan_id: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00]+$")
    snapshot_generation: str | None = Field(default=None, min_length=1, max_length=256, pattern=r"^[^\x00]+$")

    @field_validator("scan_id", "snapshot_generation")
    @classmethod
    def valid_identity(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("snapshot identity must not be blank")
        return value


class GraphConsequenceResponse(ConsequenceAssessment):
    snapshot_generation: str


def assess_snapshot_consequences(store: Any, body: GraphConsequenceRequest, *, tenant_id: str) -> GraphConsequenceResponse:
    identity = pin_generation(store, tenant=tenant_id, scan_id=body.scan_id, generation=body.snapshot_generation, offset=0)
    if not identity[1]:
        raise HTTPException(404, "Graph snapshot not found.")
    roots = list(dict.fromkeys([body.root_node_id, *([body.affected_node_id] if body.affected_node_id else [])]))
    deadline = time.monotonic() + 2.5
    graph, _, truncated = store.traverse_subgraph(
        tenant_id=tenant_id,
        scan_id=identity[0],
        roots=roots,
        direction="forward",
        max_depth=body.max_depth + 1,
        max_nodes=4096,
        max_edges=8192,
        deadline_monotonic=deadline,
        traversable_only=False,
    )
    if graph.tenant_id != tenant_id or graph.scan_id != identity[0]:
        raise HTTPException(409, "Graph snapshot scope changed; restart the assessment.")
    if body.root_node_id not in graph.nodes:
        raise HTTPException(404, "Consequence root not found in this snapshot.")
    graph.completeness.truncated = truncated or graph.completeness.truncated
    request = ConsequenceRequest.model_validate(body.model_dump(exclude={"scan_id", "snapshot_generation"}))
    try:
        result = assess_consequences(graph, request, tenant_id=tenant_id, at=datetime.now(timezone.utc), deadline_monotonic=deadline)
    except ValueError as exc:
        raise HTTPException(422, "Select a recorded agent/principal or a vulnerability and its affected occurrence.") from exc
    verify_generation(store, tenant=tenant_id, identity=identity, has_rows=True)
    return GraphConsequenceResponse(**result.model_dump(), snapshot_generation=identity[1])
