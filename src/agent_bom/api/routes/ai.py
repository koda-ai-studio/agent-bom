"""AI advice status and on-demand graph explanation. Off until an operator turns it on."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

import anyio
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.ai_components.ai_policy import control_plane_decision, control_plane_model
from agent_bom.ai_components.call_audit import AICallAuditError, ai_call_scope
from agent_bom.ai_components.call_state import _AI_DETERMINISTIC_OVERRIDE, _AI_RUN_ID
from agent_bom.ai_components.graph_explain import MAX_CONTEXT_NODES, build_explain_context, explain_graph_selection
from agent_bom.ai_components.provider_discovery import _resolve_ai_provider
from agent_bom.api.ai_assessment_read import ai_status
from agent_bom.api.ai_call_sink import ensure_ai_call_sink
from agent_bom.api.ai_explain_limits import consume_explain_allowance
from agent_bom.api.graph_node_alias import resolve_snapshot_node_ids
from agent_bom.api.graph_page_context import paths_for_sources
from agent_bom.api.graph_scan_ids import resolve_graph_scan_id
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.ai_advice import AIStatusResponse, GraphExplanationResponse
from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure

router = APIRouter()

_MAX_NODE_ID = 512


class GraphExplainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=_MAX_NODE_ID)]], Field(min_length=1, max_length=MAX_CONTEXT_NODES)
    ]
    ordered: bool = Field(default=False, description="Treat node_ids as an ordered path, so missing or non-traversable hops are reported")
    scan_id: str | None = Field(default=None, max_length=512, description="Graph scan id; defaults to the latest snapshot")


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


@router.get("/ai/status", **documented(AIStatusResponse), tags=["ai"])
async def get_ai_status(request: Request) -> dict[str, Any]:
    """Whether AI advice is on for this tenant, why, and how its last scan run went. Never calls a model."""
    tenant_id = require_request_tenant_id(request)
    decision = control_plane_decision(tenant_id)
    model = control_plane_model("") if decision.enabled else ""
    return await anyio.to_thread.run_sync(lambda: ai_status(tenant_id, enabled=decision.enabled, reason=decision.reason, model=model))


def _read_selection(tenant_id: str, body: GraphExplainRequest) -> tuple[list[Any], list[Any], list[Any]]:
    store = _get_graph_store()
    scan_id = resolve_graph_scan_id(tenant_id, body.scan_id or "")
    requested, _aliases = resolve_snapshot_node_ids(store, tenant_id=tenant_id, scan_id=scan_id, node_ids=list(body.node_ids))
    wanted = set(requested)
    nodes = store.nodes_by_ids(scan_id=scan_id, tenant_id=tenant_id, node_ids=wanted)
    found = {node.id for node in nodes}
    if not nodes or found != wanted:
        raise HTTPException(status_code=404, detail="One or more nodes are not in this tenant's graph.")
    edges = store.edges_for_node_ids(scan_id=scan_id, tenant_id=tenant_id, node_ids=wanted)
    paths = paths_for_sources(store, scan_id=scan_id, tenant_id=tenant_id, source_ids=wanted)
    covered = [path for path in paths if wanted <= {path.source, path.target, *path.hops}]
    ordered = {node_id: index for index, node_id in enumerate(requested)}
    return sorted(nodes, key=lambda node: ordered[node.id]), edges, covered


def _call_explain(tenant_id: str, actor: str, context: Any, model: str, provider: str, scan_id: str) -> dict[str, Any]:
    """A private event loop on a worker thread: a slow model never touches the server's loop."""

    async def run() -> dict[str, Any]:
        result = await explain_graph_selection(context, model=model, provider=provider)
        return result.to_dict()

    # A tenant's cached answers stay that tenant's, keyed to the snapshot they describe.
    run_token = _AI_RUN_ID.set(f"explain:{tenant_id}:{scan_id}")
    deterministic = _AI_DETERMINISTIC_OVERRIDE.set(True)
    try:
        with ai_call_scope(tenant_id=tenant_id, actor=actor, audit_required=True):
            return asyncio.run(run())
    finally:
        _AI_DETERMINISTIC_OVERRIDE.reset(deterministic)
        _AI_RUN_ID.reset(run_token)


@router.post("/graph/explain", **documented(GraphExplanationResponse), tags=["graph"])
async def post_graph_explain(request: Request, body: GraphExplainRequest) -> dict[str, Any]:
    """Explain a recorded path or selection as AI advice, citing real node and edge ids. Writes nothing."""
    tenant_id = require_request_tenant_id(request)
    decision = control_plane_decision(tenant_id)
    if not decision.enabled:
        raise HTTPException(status_code=409, detail={"state": "off", "reason": decision.reason, "message": decision.reason})
    model = control_plane_model("")
    resolution = _resolve_ai_provider(model) if model else None
    if resolution is None or not resolution.available:
        reason = resolution.reason if resolution else "The operator has not set AGENT_BOM_AI_CONTROL_PLANE_MODEL."
        raise HTTPException(status_code=409, detail={"state": "unavailable", "reason": reason, "message": reason})
    actor = _actor(request)
    ensure_ai_call_sink()
    try:
        async with adaptive_backpressure("ai_explain"):
            nodes, edges, paths = await anyio.to_thread.run_sync(_read_selection, tenant_id, body)
            denied = await anyio.to_thread.run_sync(consume_explain_allowance, tenant_id)
            if denied is not None:
                raise HTTPException(status_code=429, detail=denied.message, headers={"Retry-After": str(denied.retry_after_seconds)})
            hops = [node.id for node in nodes] if body.ordered else None
            context = build_explain_context(nodes, edges, hops=hops, attack_paths=paths)
            provider = resolution.provider.name if resolution.provider else "unknown"
            return await anyio.to_thread.run_sync(
                _call_explain, tenant_id, actor, context, resolution.model, provider, body.scan_id or "latest"
            )
    except AICallAuditError as exc:
        message = "The explanation was withheld because its audit record could not be written."
        raise HTTPException(status_code=503, detail={"state": "audit_unavailable", "reason": message, "message": message}) from exc
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
