"""Runtime activity, authorization and retention projections."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone


def _alert_visible_to_tenant(alert: dict, tenant_id: str) -> bool:
    """Scope process-wide proxy alerts to the authenticated tenant.

    Historical single-user/local records may not have a tenant tag. Keep those
    visible only to the default tenant so they do not leak into authenticated
    customer tenants on shared deployments.
    """
    alert_tenant = str(alert.get("tenant_id") or "default")
    return alert_tenant == tenant_id


def _summarize_proxy_alerts(alerts: list[dict]) -> dict:
    """Build a compact summary for proxy status and alert APIs."""
    severity_counts: Counter[str] = Counter()
    detector_counts: Counter[str] = Counter()
    blocked_alerts = 0
    recent_alerts: list[dict] = []

    for alert in sorted(alerts, key=lambda item: str(item.get("ts", "")), reverse=True):
        severity = str(alert.get("severity", "unknown")).lower()
        detector = str(alert.get("detector", "unknown"))
        severity_counts[severity] += 1
        detector_counts[detector] += 1
        details = alert.get("details", {})
        if isinstance(details, dict) and details.get("action") == "blocked":
            blocked_alerts += 1
        if len(recent_alerts) < 5:
            recent_alerts.append(
                {
                    "ts": alert.get("ts", ""),
                    "detector": detector,
                    "severity": severity,
                    "message": alert.get("message", ""),
                }
            )

    return {
        "total_alerts": len(alerts),
        "blocked_alerts": blocked_alerts,
        "alerts_by_severity": dict(sorted(severity_counts.items())),
        "alerts_by_detector": dict(sorted(detector_counts.items())),
        "latest_alert_at": recent_alerts[0]["ts"] if recent_alerts else "",
        "recent_alerts": recent_alerts,
    }


def _safe_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float | str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _safe_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float | str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _numeric_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for raw_key, raw_count in value.items():
        key = str(raw_key or "unknown")
        result[key] = max(0, _safe_int(raw_count))
    return dict(sorted(result.items()))


def _top_items(counts: Counter[str] | dict[str, int], *, limit: int = 10) -> list[dict[str, object]]:
    if isinstance(counts, Counter):
        items = counts.most_common(limit)
    else:
        items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"name": name, "count": count} for name, count in items]


def _timestamp_value(value: object) -> float:
    if isinstance(value, int | float):
        return float(value)
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _latest_timestamp(values: list[object]) -> str:
    candidates = [value for value in values if value]
    if not candidates:
        return ""
    latest = max(candidates, key=_timestamp_value)
    return str(latest)


def _runtime_retention_posture() -> dict[str, object]:
    return {
        "default_mode": "redacted",
        "modes": {
            "audit_full": "Operator-controlled local JSONL or downstream SIEM retention; not returned by the production index.",
            "redacted": "Safe-to-store runtime alerts after secret sanitization and evidence-tier redaction.",
            "metadata_only": (
                "Counts, tool names, detector names, source IDs, and trace/session references without raw arguments or payloads."
            ),
            "no_persist": "Raw prompts, raw tool arguments, raw responses, credential values, and unredacted screenshots.",
        },
        "event_classes": {
            "proxy_alerts": "redacted",
            "runtime_analytics_events": "metadata_only",
            "production_index": "metadata_only",
            "control_plane_audit_summary": "metadata_only",
            "raw_tool_arguments": "no_persist",
            "raw_tool_responses": "no_persist",
        },
        "guarantees": [
            "tenant-scoped HTTP reads",
            "secret values sanitized before persistence",
            "raw arguments excluded from production-index responses",
            "runtime events correlate by source_id, session_id, request_id, and trace_id when present",
        ],
    }


def _classify_authorization_event(alert: dict) -> str:
    action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "").lower()
    detector = str(alert.get("detector") or "").lower()
    effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
    message = str(alert.get("message") or "").lower()
    haystack = " ".join((action, detector, effective, message))
    if "approval_required" in haystack or "approval required" in haystack or effective == "warn":
        return "approval_required"
    if "data_filter" in haystack or "data filter" in haystack or "redact" in haystack or "mask" in haystack:
        return "data_filter_applied"
    if "block" in haystack or "deny" in haystack or effective == "deny":
        return "blocked"
    if "allow" in haystack or "authorized" in haystack or effective == "allow":
        return "authorized"
    return "observed"


def _authorization_trace(*, allowed_tool_calls: int, blocked_tool_calls: int, alerts: list[dict]) -> dict[str, object]:
    """Return accountable runtime authorization counts without raw arguments."""
    from agent_bom.api.proxy_provenance import projected_producer_assurance

    trace_counts: Counter[str] = Counter()
    recent: list[dict[str, object]] = []
    for alert in sorted(alerts, key=lambda item: str(item.get("ts") or item.get("timestamp") or ""), reverse=True):
        trace_class = _classify_authorization_event(alert)
        if trace_class != "observed":
            trace_counts[trace_class] += 1
        if len(recent) < 10:
            recent.append(
                {
                    "ts": alert.get("ts") or alert.get("timestamp") or alert.get("event_timestamp") or "",
                    "trace_class": trace_class,
                    "producer_assurance": projected_producer_assurance(alert),
                    "source_id": alert.get("source_id") or "unknown",
                    "session_id": alert.get("session_id") or "unknown",
                    "tool_name": alert.get("tool_name") or alert.get("tool") or "",
                    "decision": alert.get("effective_decision") or alert.get("decision") or "",
                    "detector": alert.get("detector") or "",
                }
            )
    return {
        "authorized": max(0, allowed_tool_calls + trace_counts["authorized"]),
        "blocked": max(0, blocked_tool_calls + trace_counts["blocked"]),
        "data_filter_applied": trace_counts["data_filter_applied"],
        "approval_required": trace_counts["approval_required"],
        "recent": recent,
        "retention": "metadata_only",
    }


def _build_runtime_production_index(tenant_id: str, metrics: dict | None, alerts: list[dict]) -> dict[str, object]:
    from agent_bom.api.proxy_provenance import producer_assurance_counts, producer_assurance_rollup

    metrics = dict(metrics or {})
    assurance_counts = producer_assurance_counts(alerts + ([metrics] if metrics else []))
    alert_summary = _summarize_proxy_alerts(alerts)
    calls_by_tool = _numeric_mapping(metrics.get("calls_by_tool"))
    blocked_by_reason = _numeric_mapping(metrics.get("blocked_by_reason"))
    total_tool_calls = max(_safe_int(metrics.get("total_tool_calls")), sum(calls_by_tool.values()))
    total_blocked = max(
        _safe_int(metrics.get("total_blocked")),
        sum(blocked_by_reason.values()),
        _safe_int(alert_summary["blocked_alerts"]),
    )
    allowed_tool_calls = max(0, total_tool_calls - total_blocked)

    source_counts: Counter[str] = Counter()
    session_counts: Counter[str] = Counter()
    gateway_action_counts: Counter[str] = Counter()
    for alert in alerts:
        source_id = str(alert.get("source_id") or "unknown")
        session_id = str(alert.get("session_id") or "unknown")
        action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "runtime_alert")
        source_counts[source_id] += 1
        session_counts[session_id] += 1
        if action.startswith("gateway."):
            gateway_action_counts[action] += 1

    if metrics.get("source_id"):
        source_counts[str(metrics["source_id"])] += 0
    if metrics.get("session_id"):
        session_counts[str(metrics["session_id"])] += 0

    latest_alert_at = _latest_timestamp([alert.get("ts") or alert.get("timestamp") or alert.get("event_timestamp") for alert in alerts])
    metrics_received_at = str(metrics.get("received_at") or metrics.get("ts") or "")
    block_rate = (total_blocked / total_tool_calls) if total_tool_calls else 0.0
    latency = metrics.get("latency") if isinstance(metrics.get("latency"), dict) else {}

    return {
        "schema_version": "runtime.production_index.v1",
        "producer_assurance": producer_assurance_rollup(assurance_counts),
        "producer_assurance_counts": assurance_counts,
        "producer_assurance_count_basis": "submissions",
        "evidence_basis": "submitted_runtime_activity",
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok" if metrics or alerts else "no_runtime_activity",
        "traffic": {
            "total_tool_calls": total_tool_calls,
            "allowed_tool_calls": allowed_tool_calls,
            "blocked_tool_calls": total_blocked,
            "block_rate": round(block_rate, 4),
            "calls_by_tool": calls_by_tool,
            "top_tools": _top_items(calls_by_tool),
            "blocked_by_reason": blocked_by_reason,
            "uptime_seconds": _safe_float(metrics.get("uptime_seconds")),
            "latency_p95_ms": _safe_float(latency.get("p95_ms")) if latency else None,
        },
        "policy_decisions": {
            "allowed": allowed_tool_calls,
            "blocked": total_blocked,
            "gateway_actions": dict(sorted(gateway_action_counts.items())),
        },
        "authorization_trace": _authorization_trace(
            allowed_tool_calls=allowed_tool_calls,
            blocked_tool_calls=total_blocked,
            alerts=alerts,
        ),
        "alerts": {key: value for key, value in alert_summary.items() if key != "recent_alerts"},
        "active_sources": _top_items(source_counts),
        "active_sessions": _top_items(session_counts),
        "freshness": {
            "has_metrics": bool(metrics),
            "has_alerts": bool(alerts),
            "metrics_received_at": metrics_received_at,
            "latest_alert_at": latest_alert_at,
        },
        "retention_posture": _runtime_retention_posture(),
    }
