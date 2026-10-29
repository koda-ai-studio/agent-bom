"""Pure projection helpers for the gateway live feed.

Normalizes proxy alerts and priced LLM cost records into the single feed
event shape consumed by :mod:`agent_bom.api.routes.gateway_feed`. No I/O:
every helper here is a pure function over already tenant-scoped records so
ordering, action classification and redaction-safety are unit-testable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api.proxy_provenance import projected_producer_assurance
from agent_bom.runtime.gateway_events import (
    GATEWAY_ALLOWED_EVENT_TYPES,
    GATEWAY_BLOCKED_EVENT_TYPES,
    GATEWAY_CANONICAL_EVENT_TYPES,
    GATEWAY_DATA_FILTER_EVENT_TYPES,
    GATEWAY_ENFORCEMENT_EVENT_TYPES,
    GATEWAY_PROFILE_EVENT_TYPES,
)
from agent_bom.runtime.profile_resolution import classify_profile_shadow_reason

# Action classes for a fused gateway feed event. Kept in sync with the badge
# vocabulary the UI renders.
ACTION_TOOL_CALL_AUTHORIZED = "tool_call_authorized"
ACTION_TOOL_CALL_BLOCKED = "tool_call_blocked"
ACTION_DATA_FILTER_APPLIED = "data_filter_applied"
ACTION_LLM_CALL = "llm_call"
_EVENT_TYPES = GATEWAY_CANONICAL_EVENT_TYPES

# Block reasons that indicate a shadow / undeclared agent or shadow MCP server
# rather than an ordinary policy block. ``undeclared`` is emitted by the proxy
# block-undeclared enforcement (``proxy.undeclared_tool_block_reason``); the
# others cover unknown-agent / shadow-server gateway blocks.
# Canonical sanctioned-client enforcement. The gateway resolves every caller
# against its ``McpClientConfigAssignment`` and emits the outcome as a stable
# ``reason_code`` (``gateway_server`` -> ``profile_failure_code``). Deriving the
# shadow-AI KPI from these codes rather than from free-text markers is the
# difference between "we inferred this looked like shadow AI" and "the gateway
# refused to attribute this caller to a sanctioned profile".
#
# Codes are imported, never re-spelled here: one judgement, one implementation.
_SHADOW_BLOCK_MARKERS = (
    "undeclared",
    "shadow",
    "unknown_agent",
    "unknown agent",
    "unregistered",
    "unknown-agent",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert_timestamp(alert: dict[str, Any]) -> str:
    """Return a best-effort ISO-8601 timestamp for a proxy alert record.

    Proxy alerts carry either an epoch float ``ts`` or an ISO string
    ``timestamp`` / ``event_timestamp``. Normalize to ISO-8601 so all fused
    event sources sort on one comparable string key.
    """
    raw_ts = alert.get("ts")
    if isinstance(raw_ts, int | float) and raw_ts > 0:
        try:
            return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    for key in ("timestamp", "event_timestamp", "received_at"):
        value = alert.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _sort_key(event: dict[str, Any]) -> str:
    """Sort key for fused events — newest first when reversed.

    Normalizes the ``ts`` ISO strings into a comparable form. Events without a
    timestamp sort last (oldest) by mapping to the empty string.
    """
    return str(event.get("ts") or "")


def _feed_order_key(event: dict[str, Any]) -> tuple[int, int, str]:
    """Prefer the server-owned ledger ordinal over caller timestamps."""

    ordinal = event.get("ingest_ordinal")
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal > 0:
        return (1, ordinal, "")
    return (0, 0, _sort_key(event))


def _alert_agent(alert: dict[str, Any]) -> str:
    """Per-agent attribution for a proxy alert.

    Prefer the explicit agent name; fall back to source_id (the proxied agent
    process identifier) and finally to ``"unknown"`` so every event in the feed
    carries a visible actor.
    """
    for key in ("agent_name", "agent", "agent_id", "source_agent", "source_id"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _alert_target(alert: dict[str, Any]) -> str:
    for key in ("tool_name", "tool", "upstream", "target"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _bounded_alert_identifier(alert: dict[str, Any], key: str) -> str:
    value = alert.get(key)
    if not isinstance(value, str):
        return ""
    return value.strip()[:200]


def _alert_revision(alert: dict[str, Any], key: str) -> int:
    value = alert.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _alert_policy_ids(alert: dict[str, Any]) -> list[str]:
    raw_policy_ids = alert.get("policy_ids")
    if not isinstance(raw_policy_ids, list | tuple):
        return []
    policy_ids: list[str] = []
    for value in raw_policy_ids:
        if not isinstance(value, str):
            continue
        normalized = value.strip()[:200]
        if normalized and normalized not in policy_ids:
            policy_ids.append(normalized)
        if len(policy_ids) == 200:
            break
    return policy_ids


def _is_shadow_block(alert: dict[str, Any]) -> bool:
    """True when a blocked event is a shadow / undeclared-agent or shadow-server block.

    Inspects the markers the proxy/gateway emit for undeclared tools and unknown
    agents. Free-text fields (``reason`` / ``message`` / ``action`` /
    ``details.reason``) are present on direct in-process alerts but are stripped
    by tier-A redaction before they reach the persisted ring buffer, so this
    also inspects the redaction-safe whitelisted fields (``event_type``,
    ``detector``, ``reason_code``, ``policy_source``, ``policy_result``,
    ``outcome``) that survive ``redact_for_persistence``. Used both to label
    feed events and to roll up the ``shadow_ai_blocked`` KPI.
    """
    # Canonical profile enforcement wins outright when the gateway recorded it.
    # Only fall through to marker inference when no recognized code is present
    # (direct in-process alerts from a standalone proxy, and older records).
    canonical = classify_profile_shadow_reason(str(alert.get("reason_code") or ""))
    if canonical is not None:
        return canonical

    details = alert.get("details")
    detail_reason = ""
    if isinstance(details, dict):
        detail_reason = str(details.get("reason") or details.get("block_reason") or "")
    haystack = " ".join(
        str(part).lower()
        for part in (
            detail_reason,
            # Free-text — survives on direct in-process alerts only.
            alert.get("reason"),
            alert.get("action"),
            alert.get("message"),
            # Redaction-safe (tier-A whitelist) — survives the ring buffer.
            alert.get("detector"),
            alert.get("event_type"),
            alert.get("reason_code"),
            alert.get("policy_source"),
            alert.get("policy_result"),
            alert.get("outcome"),
        )
        if part
    )
    return any(marker in haystack for marker in _SHADOW_BLOCK_MARKERS)


def _block_detail(alert: dict[str, Any]) -> str:
    details = alert.get("details")
    if isinstance(details, dict):
        reason = details.get("reason") or details.get("block_reason")
        if isinstance(reason, str) and reason.strip():
            return reason.strip()[:200]
    reason = alert.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()[:200]
    if _is_shadow_block(alert):
        return "shadow / undeclared agent blocked"
    # Redaction-safe coded reason survives the ring buffer when free text does not.
    reason_code = alert.get("reason_code")
    if isinstance(reason_code, str) and reason_code.strip():
        return reason_code.strip()[:200]
    return "blocked by gateway policy"


def _data_filter_detail(alert: dict[str, Any]) -> str:
    """Human-readable, secret-free detail for a DLP / redaction event.

    Surfaces what class of data was masked (e.g. "PII redacted",
    "credential masked") using the sanitized credential_type/pii_type metadata
    already present on the alert. Never returns raw matched values — the source
    record only retains redacted previews.
    """
    data_action = str(alert.get("data_action") or "").strip().lower()
    if data_action == "pii_redacted":
        return "PII redacted"
    if data_action == "visual_redacted":
        return "visual leak redacted"
    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    detector = str(alert.get("detector") or "").lower()
    cred_type = ""
    pii_type = ""
    if isinstance(details, dict):
        cred_type = str(details.get("credential_type") or "")
        pii_type = str(details.get("pii_type") or details.get("pii_name") or "")
    if cred_type:
        return f"{cred_type} credential masked"
    if pii_type:
        return f"{pii_type} PII redacted"
    if "credential" in detector:
        return "credential masked"
    if "pii" in detector:
        return "PII redacted"
    if "visual" in detector:
        return "visual leak redacted"
    return "sensitive data masked"


def _classify_alert_action(alert: dict[str, Any]) -> str | None:
    """Map a proxy alert to a unified feed action class, or None to skip.

    Reuses the same decision vocabulary the proxy production index uses
    (``action`` / ``effective_decision`` / ``detector`` / ``message``) so this
    feed stays consistent with ``/v1/runtime/production-index``.
    """
    event_type = str(alert.get("event_type") or "").lower()
    if event_type in GATEWAY_PROFILE_EVENT_TYPES | GATEWAY_ENFORCEMENT_EVENT_TYPES:
        # Profile and enforcement posture are evidence, not tool calls.
        # A later surface slice can render it as a dedicated activity class;
        # never inflate authorized/blocked call counts in the compatibility UI.
        return None
    if event_type in GATEWAY_DATA_FILTER_EVENT_TYPES or event_type == "gateway.visual_leak_blocked":
        return ACTION_DATA_FILTER_APPLIED
    if event_type in GATEWAY_BLOCKED_EVENT_TYPES:
        return ACTION_TOOL_CALL_BLOCKED
    if event_type in GATEWAY_ALLOWED_EVENT_TYPES:
        return ACTION_TOOL_CALL_AUTHORIZED

    # Backward-compatible inference for historical proxy-shaped events. New
    # standalone-gateway events are classified only by the exact types above.
    action = str(alert.get("action") or event_type or alert.get("type") or "").lower()
    detector = str(alert.get("detector") or "").lower()
    effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
    message = str(alert.get("message") or "").lower()
    haystack = " ".join((action, detector, effective, message))

    if "redact" in haystack or "mask" in haystack or "data_filter" in haystack or "data filter" in haystack:
        return ACTION_DATA_FILTER_APPLIED
    if detector in {"credential_leak", "pii", "pii_leak"} or "leak" in detector:
        return ACTION_DATA_FILTER_APPLIED
    if "block" in haystack or "deny" in haystack or effective == "deny":
        return ACTION_TOOL_CALL_BLOCKED
    if "allow" in haystack or "authorized" in haystack or effective == "allow":
        return ACTION_TOOL_CALL_AUTHORIZED
    return None


def _normalize_alert_event(alert: dict[str, Any], tenant_id: str) -> dict[str, Any] | None:
    """Project one proxy alert into a normalized feed event, or None to skip."""
    action_type = _classify_alert_action(alert)
    if action_type is None:
        return None
    agent = _alert_agent(alert)
    target = _alert_target(alert)
    if action_type == ACTION_TOOL_CALL_BLOCKED:
        detail = _block_detail(alert)
        shadow = _is_shadow_block(alert)
    elif action_type == ACTION_DATA_FILTER_APPLIED:
        detail = _data_filter_detail(alert)
        shadow = False
    else:
        detail = "authorized"
        shadow = False
    return {
        "producer_assurance": projected_producer_assurance(alert),
        "event_id": str(alert.get("event_id") or ""),
        "decision_id": _bounded_alert_identifier(alert, "decision_id"),
        "ts": _alert_timestamp(alert),
        "agent": agent,
        "identity_id": _bounded_alert_identifier(alert, "identity_id"),
        "profile_id": _bounded_alert_identifier(alert, "profile_id"),
        "profile_revision": _alert_revision(alert, "profile_revision"),
        "blueprint_id": _bounded_alert_identifier(alert, "blueprint_id"),
        "blueprint_revision": _alert_revision(alert, "blueprint_revision"),
        "policy_ids": _alert_policy_ids(alert),
        "reason_code": _bounded_alert_identifier(alert, "reason_code"),
        "development_mode": alert.get("development_mode") is True,
        "action_type": action_type,
        "target": target,
        "upstream": str(alert.get("upstream") or ""),
        "decision": str(alert.get("decision") or alert.get("outcome") or ""),
        "data_action": str(alert.get("data_action") or ""),
        "policy_source": str(alert.get("policy_source") or ""),
        "trace_id": str(alert.get("trace_id") or ""),
        "detail": detail,
        "tenant": tenant_id,
        "shadow": shadow,
        "source": (
            "gateway_activity_ledger" if str(alert.get("record_schema_version") or "").startswith("gateway.activity.record.") else "proxy"
        ),
        "ingest_ordinal": (
            int(alert["ingest_ordinal"]) if isinstance(alert.get("ingest_ordinal"), int) and int(alert["ingest_ordinal"]) > 0 else None
        ),
    }


def _normalize_llm_event(record: Any, tenant_id: str) -> dict[str, Any]:
    """Project one priced LLM cost record into a normalized feed event."""
    provider = str(getattr(record, "provider", "") or "")
    model = str(getattr(record, "model", "") or "")
    target = "/".join(part for part in (provider, model) if part) or "llm"
    agent = str(getattr(record, "agent", "") or "").strip() or "unknown"
    cost = getattr(record, "cost_usd", 0.0)
    input_tokens = getattr(record, "input_tokens", 0) or 0
    output_tokens = getattr(record, "output_tokens", 0) or 0
    priced = bool(getattr(record, "priced", False))
    if priced and isinstance(cost, int | float) and cost > 0:
        detail = f"${float(cost):.4f} · {int(input_tokens) + int(output_tokens)} tokens"
    else:
        detail = f"{int(input_tokens) + int(output_tokens)} tokens"
    return {
        "event_id": "",
        "decision_id": "",
        "ts": str(getattr(record, "observed_at", "") or ""),
        "agent": agent,
        "identity_id": "",
        "profile_id": "",
        "profile_revision": 0,
        "blueprint_id": "",
        "blueprint_revision": 0,
        "policy_ids": [],
        "reason_code": "",
        "development_mode": False,
        "action_type": ACTION_LLM_CALL,
        "target": target,
        "upstream": "",
        "decision": "allow",
        "data_action": "",
        "policy_source": "observability",
        "trace_id": str(getattr(record, "trace_id", "") or ""),
        "detail": detail,
        "tenant": tenant_id,
        "shadow": False,
        "source": "observability",
        "producer_assurance": "unknown",
        "ingest_ordinal": None,
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cost_usd": float(cost) if priced and isinstance(cost, int | float) else None,
    }
