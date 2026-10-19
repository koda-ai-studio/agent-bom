"""Trace cost allocation and tenant cost projections."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from starlette.responses import Response

from agent_bom.api.observability_events import _bounded, _logger, _now
from agent_bom.api.stores import _get_fleet_store

_COST_CENTER_KEYS = ("agent.cost_center", "gen_ai.cost_center", "cost_center")


_ALLOCATION_TAG_PREFIX = "allocation.tag."


_MAX_ALLOCATION_TAGS = 16


def _attr_str(attr_value: Any) -> str:
    if not isinstance(attr_value, dict):
        return ""
    return str(attr_value.get("stringValue") or attr_value.get("intValue") or attr_value.get("doubleValue") or "").strip()


def _allocation_for_spans(body: dict) -> dict[str, tuple[str, dict[str, str]]]:
    """Map ``trace_id:span_id`` -> (cost_center, allocation_tags) from OTLP attrs.

    Span-level attributes win over resource-level ones, so a per-call override
    beats a service-wide default. Tolerant of any non-OTLP shape (returns {}).
    """
    out: dict[str, tuple[str, dict[str, str]]] = {}
    try:
        resource_spans = body.get("resourceSpans") if isinstance(body, dict) else None
        if not isinstance(resource_spans, list):
            return out
        for rs in resource_spans:
            res_cc, res_tags = _read_allocation_attrs(rs.get("resource", {}).get("attributes", []) if isinstance(rs, dict) else [])
            for ss in rs.get("scopeSpans", []) if isinstance(rs, dict) else []:
                for span in ss.get("spans", []) if isinstance(ss, dict) else []:
                    if not isinstance(span, dict):
                        continue
                    span_cc, span_tags = _read_allocation_attrs(span.get("attributes", []))
                    merged_tags = {**res_tags, **span_tags}
                    cost_center = span_cc or res_cc
                    call_id = f"{span.get('traceId', '')}:{span.get('spanId', '')}"
                    out[call_id] = (cost_center, merged_tags)
    except Exception:  # noqa: BLE001
        return {}
    return out


def _read_allocation_attrs(attributes: Any) -> tuple[str, dict[str, str]]:
    cost_center = ""
    tags: dict[str, str] = {}
    if not isinstance(attributes, list):
        return cost_center, tags
    for attr in attributes:
        if not isinstance(attr, dict):
            continue
        key = str(attr.get("key", "")).strip()
        value = _attr_str(attr.get("value", {}))
        if not key or not value:
            continue
        if key in _COST_CENTER_KEYS and not cost_center:
            cost_center = _bounded(value, max_len=120)
        elif key.startswith(_ALLOCATION_TAG_PREFIX) and len(tags) < _MAX_ALLOCATION_TAGS:
            tag_name = _bounded(key[len(_ALLOCATION_TAG_PREFIX) :], max_len=60)
            if tag_name:
                tags[tag_name] = _bounded(value, max_len=120)
    return cost_center, tags


def _persist_llm_costs(body: dict, *, tenant_id: str) -> dict[str, Any]:
    """Price GenAI spans in an OTLP payload and persist per-call cost records.

    Token counts come from OTel GenAI semantic conventions; cost is the open
    price model in agent_bom.cost_model. Chargeback allocation (cost_center +
    allocation tags) is read from span/resource attributes. Failures never
    block trace ingest.
    """
    try:
        from agent_bom.api.cost_store import LLMCostRecord, get_cost_store
        from agent_bom.cost_model import compute_cost_usd, is_priced
        from agent_bom.otel_ingest import parse_ml_api_spans

        calls = parse_ml_api_spans(body)
    except Exception:  # noqa: BLE001
        _logger.warning("LLM cost ingest skipped", exc_info=False)
        return {"calls": 0, "cost_usd": 0.0}

    allocation = _allocation_for_spans(body)
    store = get_cost_store()
    total = 0.0
    observed = _now()
    for call in calls:
        cost = compute_cost_usd(call.provider, call.model_name, call.input_tokens, call.output_tokens)
        total += cost
        agent = _bounded(getattr(call, "agent", "") or "", max_len=120)
        call_id = f"{call.trace_id}:{call.span_id}"
        cost_center, allocation_tags = allocation.get(call_id, ("", {}))
        store.record_cost(
            LLMCostRecord(
                tenant_id=tenant_id,
                call_id=call_id,
                agent=agent,
                session_id=call.trace_id,
                provider=_bounded(call.provider, max_len=60),
                model=_bounded(call.model_name, max_len=120),
                input_tokens=max(0, int(call.input_tokens)),
                output_tokens=max(0, int(call.output_tokens)),
                cost_usd=cost,
                priced=is_priced(call.provider, call.model_name),
                observed_at=observed,
                cost_center=cost_center,
                allocation_tags=allocation_tags,
            )
        )
    return {"calls": len(calls), "cost_usd": round(total, 6)}


async def _render_prometheus_metrics(request: Request | None = None) -> Response:
    """Prometheus scrape endpoint — exposes control-plane and pilot metrics.

    Catalog lives in docs/OBSERVABILITY_METRICS.md — keep that doc in sync
    when adding or renaming series here.
    """
    from starlette.responses import Response

    try:
        from agent_bom.api.metrics import render_prometheus_lines
        from agent_bom.api.oidc import oidc_decode_failure_count

        store = _get_fleet_store()
        tenant_id = getattr(getattr(request, "state", None), "tenant_id", "").strip() if request is not None else ""
        # /metrics may be scraped without a tenant-bound auth context. Avoid
        # aggregating fleet gauges across every tenant in that case.
        agents = store.list_by_tenant(tenant_id) if tenant_id else []
        lines = [
            "# HELP agent_bom_fleet_total Total agents in fleet",
            "# TYPE agent_bom_fleet_total gauge",
            f"agent_bom_fleet_total {len(agents)}",
            "# HELP agent_bom_fleet_quarantined Quarantined agents",
            "# TYPE agent_bom_fleet_quarantined gauge",
            f"agent_bom_fleet_quarantined {sum(1 for a in agents if getattr(a, 'lifecycle_state', '') == 'quarantined')}",
            "# HELP agent_bom_oidc_decode_failures_total Failed OIDC decode or verification attempts",
            "# TYPE agent_bom_oidc_decode_failures_total counter",
            f"agent_bom_oidc_decode_failures_total {oidc_decode_failure_count()}",
        ]
        lines.extend(render_prometheus_lines())
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")
    except Exception:  # noqa: BLE001
        return Response("# No metrics available\n", media_type="text/plain; version=0.0.4; charset=utf-8")


def _build_llm_costs_report_sync(
    tenant_id: str,
    *,
    agent: str | None,
    cost_center: str | None,
    tag: str | None,
    limit: int,
) -> dict[str, object]:
    """Fetch + compute the LLM cost report off the event loop."""
    from agent_bom.api.cost_forecast import forecast_spend
    from agent_bom.api.cost_owner import owner_cost_report
    from agent_bom.api.cost_store import budget_status, get_cost_store, summarize, summarize_by_tag

    store = get_cost_store()
    records = store.list_records(tenant_id, limit=limit, agent=agent, cost_center=cost_center)
    report = summarize(records)
    totals = store.report_totals(tenant_id, agent=agent, cost_center=cost_center)
    report.update(totals)
    complete = len(records) == totals["total_calls"]
    report["history"] = {"limit": limit, "returned_calls": len(records), "complete": complete}
    report["scope"] = {"agent": agent, "cost_center": cost_center}
    # Owner-attributed rollup (#3909): spend grouped by the accountable owner
    # recorded on the blueprint governing each agent. Spend from an ungoverned
    # agent rolls up under "unattributed" so nothing is silently dropped.
    report["by_owner"] = owner_cost_report(store, tenant_id, records)["by_owner"]
    if tag:
        report["tag_rollup"] = summarize_by_tag(records, _bounded(tag, max_len=60))
    if cost_center:
        spend = store.total_spend_by_cost_center(tenant_id, cost_center)
        budget = store.get_budget(tenant_id, "", cost_center=cost_center)
    else:
        spend = store.total_spend(tenant_id, agent=agent)
        budget = store.get_budget(tenant_id, agent or "")
        if budget is None and agent:
            budget = store.get_budget(tenant_id, "")
            spend = store.total_spend(tenant_id)
    report["budget"] = budget_status(spend, budget)
    # Forward-looking companion to the point-in-time budget posture: burn rate +
    # projected runway derived from the same records. Reference only.
    from agent_bom.api.cost_forecast import unavailable_forecast

    if not complete:
        report["forecast"] = unavailable_forecast("incomplete_history", totals["total_cost_usd"], budget)
    elif budget is not None and (budget.agent != (agent or "") or budget.cost_center != (cost_center or "")):
        report["forecast"] = unavailable_forecast("budget_scope_mismatch", totals["total_cost_usd"], budget)
    else:
        report["forecast"] = forecast_spend(records, budget=budget)
    report["schema_version"] = "observability.costs.v1"
    report["tenant_id"] = tenant_id
    report["price_model_captured"] = __import__("agent_bom.cost_model", fromlist=["PRICE_TABLE_CAPTURED"]).PRICE_TABLE_CAPTURED
    return report
