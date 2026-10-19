"""Tenant cost reports, budget controls and forecasts."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.observability_costs import _build_llm_costs_report_sync
from agent_bom.api.observability_events import _bounded, _dep, _now, _tenant_id
from agent_bom.api.read_models import documented, observability
from agent_bom.rbac import require_authenticated_permission

router = APIRouter()

_FINOPS_READ: dict[str, Any] = {"tags": ["observability", "finops"], "dependencies": [require_authenticated_permission("read")]}


@router.get("/observability/costs", **documented(observability.ObservabilityCostsResponse), **_FINOPS_READ)
async def get_llm_costs(
    request: Request,
    agent: str | None = None,
    cost_center: str | None = None,
    tag: str | None = None,
    limit: Annotated[int, Query(ge=1, le=10000)] = 1000,
) -> dict[str, object]:
    """Per-agent / per-model / per-provider / per-cost-center LLM spend.

    Spend is derived from token counts on ingested OTel GenAI spans priced via
    the open cost model (agent_bom.cost_model). Includes budget posture and the
    chargeback/showback rollup ``by_cost_center`` (#2925). Pass ``cost_center``
    to scope the report (and budget) to one allocation unit, or ``tag`` to add a
    ``by_tag`` showback slice for a freeform allocation tag.
    """
    tenant_id = _tenant_id(request)
    bounded_limit = max(1, min(limit, 10000))
    # The fetch (up to 10k records) plus the summarize / owner-report / budget /
    # forecast CPU work is all synchronous; offload it in one hop so a large cost
    # ledger can never block the event loop.
    return await asyncio.to_thread(
        _build_llm_costs_report_sync,
        tenant_id,
        agent=agent,
        cost_center=cost_center,
        tag=tag,
        limit=bounded_limit,
    )


@router.get("/observability/costs/budget", **documented(observability.ObservabilityCostBudgetResponse), **_FINOPS_READ)
def get_llm_cost_budget(request: Request, agent: str = "", cost_center: str = "", owner: str = "", workflow: str = "") -> dict[str, object]:
    """Return the configured spend budget and current utilization.

    Pass ``cost_center`` to read a chargeback budget scoped to one allocation
    unit (#2925), or ``owner`` (optionally with ``workflow``) to read an
    accountable-owner budget (#3909), instead of the per-agent / tenant-wide cap.
    """
    from agent_bom.api.cost_store import budget_status, get_cost_store

    tenant_id = _tenant_id(request)
    store = get_cost_store()
    if owner:
        from agent_bom.api.cost_owner import agent_owner_index, owner_spend

        budget = store.get_budget(tenant_id, "", owner=owner, workflow=workflow)
        spend = owner_spend(store, agent_owner_index(tenant_id), tenant_id, owner, workflow)
    elif cost_center:
        budget = store.get_budget(tenant_id, "", cost_center=cost_center)
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
    else:
        budget = store.get_budget(tenant_id, agent)
        spend = store.total_spend(tenant_id, agent=agent or None)
    return {"schema_version": "observability.costs.v1", "tenant_id": tenant_id, **budget_status(spend, budget)}


@router.put("/observability/costs/budget", tags=["observability", "finops"], dependencies=[_dep("config")])
def set_llm_cost_budget(request: Request, body: dict) -> dict[str, object]:
    """Set a USD spend cap. Body: {limit_usd, agent?, cost_center?, owner?, workflow?, mode?}.

    A ``cost_center`` scopes the cap to one chargeback unit (#2925); ``agent``
    scopes it to one agent; ``owner`` scopes it to an accountable human/team as
    recorded on the governing blueprint (#3909), optionally narrowed to one
    governing blueprint via ``workflow``; none set means tenant-wide. ``agent`` /
    ``cost_center`` / ``owner`` are mutually exclusive, and ``workflow`` requires
    ``owner``.
    """
    from agent_bom.api.cost_owner import owner_spend as _owner_spend
    from agent_bom.api.cost_store import CostBudget, budget_status, get_cost_store

    tenant_id = _tenant_id(request)
    raw_limit = body.get("limit_usd")
    if raw_limit is None:
        raise HTTPException(status_code=400, detail="'limit_usd' is required and must be a number")
    try:
        limit_usd = float(raw_limit)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'limit_usd' is required and must be a number") from exc
    if limit_usd < 0:
        raise HTTPException(status_code=400, detail="'limit_usd' must be non-negative")
    agent = _bounded(str(body.get("agent", "") or ""), max_len=120)
    cost_center = _bounded(str(body.get("cost_center", "") or ""), max_len=120)
    owner = _bounded(str(body.get("owner", "") or ""), max_len=200)
    workflow = _bounded(str(body.get("workflow", "") or ""), max_len=120)
    if sum(1 for scope in (agent, cost_center, owner) if scope) > 1:
        raise HTTPException(status_code=400, detail="'agent', 'cost_center' and 'owner' budgets are mutually exclusive")
    if workflow and not owner:
        raise HTTPException(status_code=400, detail="'workflow' requires an 'owner' scope")
    mode = str(body.get("mode", "report") or "report").strip().lower()
    if mode not in ("report", "enforce"):
        raise HTTPException(status_code=400, detail="'mode' must be 'report' or 'enforce'")
    store = get_cost_store()
    store.set_budget(
        CostBudget(
            tenant_id=tenant_id,
            agent=agent,
            limit_usd=limit_usd,
            updated_at=_now(),
            mode=mode,
            cost_center=cost_center,
            owner=owner,
            workflow=workflow,
        )
    )
    if owner:
        from agent_bom.api.cost_owner import agent_owner_index

        spend = _owner_spend(store, agent_owner_index(tenant_id), tenant_id, owner, workflow)
        stored = store.get_budget(tenant_id, "", owner=owner, workflow=workflow)
    elif cost_center:
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
        stored = store.get_budget(tenant_id, "", cost_center=cost_center)
    else:
        spend = store.total_spend(tenant_id, agent=agent or None)
        stored = store.get_budget(tenant_id, agent)
    return {
        "schema_version": "observability.costs.v1",
        "tenant_id": tenant_id,
        "updated": True,
        **budget_status(spend, stored),
    }


@router.get("/observability/costs/forecast", **documented(observability.ObservabilityCostForecastResponse), **_FINOPS_READ)
async def get_llm_cost_forecast(
    request: Request, agent: str | None = None, limit: Annotated[int, Query(ge=1, le=10000)] = 10000
) -> dict[str, object]:
    """Project LLM spend burn rate and budget runway for the active tenant.

    Derives a recent burn rate (trailing 24h / 7d) from ``observed_at`` on
    persisted cost records and extrapolates to the configured budget — returning
    projected period spend, days of runway, and an exhaustion date. Reference
    only: a forecast never blocks a call (enforcement stays in the relay) and
    returns a clear ``status`` with null projections on sparse/empty history.
    """
    from agent_bom.api.cost_forecast import forecast_for_tenant

    bounded_limit = max(1, min(limit, 10000))
    scoped_agent = _bounded(agent, max_len=120) if agent else None
    return await asyncio.to_thread(forecast_for_tenant, _tenant_id(request), agent=scoped_agent, limit=bounded_limit)


@router.get("/observability/anomalies", **documented(observability.ObservabilityAnomaliesResponse), **_FINOPS_READ)
def get_anomalies(request: Request, z_threshold: float = 3.0) -> dict[str, object]:
    """Detect cost and behavior anomalies (per-agent spend + per-session call-rate
    z-scores) for the active tenant. Proactive surfacing of runaway agents."""
    from agent_bom.api.anomaly import scan_anomalies

    bounded = max(1.0, min(z_threshold, 10.0))
    return scan_anomalies(_tenant_id(request), z_threshold=bounded)
