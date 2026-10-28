"""Alert-or-enforce handling of poisoned tool descriptions and injected tool results.

Shared by the stdio proxy relay and the gateway forwarding stage. ``alert``
(the default) only reports detections; ``enforce`` withholds poisoned tools
from ``tools/list`` and replaces injected tool results with a JSON-RPC error.
Enforcement emits the detection alert itself, tagged ``action``, and never
copies the upstream text into the replacement message.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from agent_bom.runtime.detectors import Alert, AlertSeverity
from agent_bom.security import sanitize_text

INJECTION_MODES = ("alert", "enforce")
INJECTION_MODE_HELP = (
    "Poisoned tool descriptions / injected tool results: alert (default) forwards them with an alert; enforce strips the "
    "poisoned tool from tools/list, refuses later calls to it, withholds the injected result and drops non-JSON-RPC "
    "upstream stdout. Only high/critical response-inspector detections (and any vector_db_injection) block; medium ones "
    "are forwarded with an alert. A policy file's injection_mode can also select enforce. See docs/RUNTIME_FAIL_MODES.md."
)
DEFAULT_INJECTION_MODE = "alert"
POLICY_KEY = "injection_mode"
POLICY_SOURCE = "injection_protection"
BLOCKED_ERROR_CODE = -32001
BLOCKED_MESSAGE = "Tool result withheld by agent-bom injection protection"
WITHHELD_TOOL_REASON = "Tool withheld by injection protection: poisoned tool description"
ENFORCED_CATEGORIES = frozenset({"prompt_injection", "semantic_injection", "cloaking", "svg_payload", "invisible_text"})
_ENFORCED_SEVERITIES = frozenset({AlertSeverity.CRITICAL, AlertSeverity.HIGH})


class InjectionModeError(ValueError):
    """Invalid or contradictory injection-protection configuration; never echoes input."""


class _TextDetector(Protocol):
    def check(self, tool_name: str, response_text: str) -> list[Alert]: ...


class _VectorDetector(_TextDetector, Protocol):
    def is_vector_tool(self, tool_name: str) -> bool: ...


def normalize_injection_mode(value: object) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else None
    if normalized not in INJECTION_MODES:
        raise InjectionModeError("injection_mode must be one of alert, enforce")
    return normalized


def resolve_injection_mode(flag: str | None, policy: Mapping[str, Any] | None, *, log_only: bool = False) -> str:
    """Strictest wins: ``enforce`` if either the flag or the policy file selects it."""
    modes = {normalize_injection_mode(flag or DEFAULT_INJECTION_MODE)}
    if policy and POLICY_KEY in policy:
        modes.add(normalize_injection_mode(policy[POLICY_KEY]))
    mode = "enforce" if "enforce" in modes else DEFAULT_INJECTION_MODE
    if mode == "enforce" and log_only:
        raise InjectionModeError("injection_mode enforce cannot be combined with log-only (advisory) mode")
    return mode


SSE_UNSUPPORTED = "injection_mode enforce is supported by the stdio proxy and the gateway, not the SSE/HTTP proxy"


def reject_unsupported_enforce(policy: Mapping[str, Any] | None) -> None:
    """Surfaces without enforcement refuse to start rather than silently alerting only."""
    if resolve_injection_mode(None, policy) == "enforce":
        raise InjectionModeError(SSE_UNSUPPORTED)


def sse_policy_supported(policy: Mapping[str, Any] | None, logger: logging.Logger) -> bool:
    try:
        reject_unsupported_enforce(policy)
    except InjectionModeError as exc:
        logger.error("Refusing to start: %s", sanitize_text(exc))
        return False
    return True


def gateway_injection_mode(setting: str | None, policy: Mapping[str, Any] | None) -> str:
    """A hot-reloaded policy with an invalid ``injection_mode`` fails closed to enforce."""
    try:
        return resolve_injection_mode(setting, policy)
    except InjectionModeError:
        return "enforce"


def is_enforceable(alert: Alert) -> bool:
    if alert.detector == "vector_db_injection":
        return True
    return (
        alert.detector == "response_inspector"
        and alert.severity in _ENFORCED_SEVERITIES
        and alert.details.get("category") in ENFORCED_CATEGORIES
    )


@dataclass(frozen=True)
class InjectionOutcome:
    """Alerts for one upstream message and the message the client may receive."""

    message: dict[str, Any]
    alerts: list[Alert]
    withheld_tools: frozenset[str] = frozenset()
    clean_tools: frozenset[str] = frozenset()
    blocked: bool = False


def _detector_failure(tool_name: str, exc: Exception) -> Alert:
    return Alert(
        detector=POLICY_SOURCE,
        severity=AlertSeverity.HIGH,
        message=f"Injection detector failed on response from {tool_name}",
        details={"tool": tool_name, "category": "detector_error", "error_type": type(exc).__name__},
    )


def _scan(payload: object, tool_name: str, inspector: _TextDetector, vector: _VectorDetector | None) -> tuple[list[Alert], bool]:
    text = json.dumps(payload)
    try:
        alerts = list(inspector.check(tool_name, text))
        if vector is not None and vector.is_vector_tool(tool_name):
            alerts.extend(vector.check(tool_name, text))
    except Exception as exc:  # broad-except: a detector fault must resolve to the profile's documented fail mode
        return [_detector_failure(tool_name, exc)], True
    return alerts, False


def _triggers(alerts: list[Alert], failed: bool) -> list[Alert]:
    return list(alerts) if failed else [alert for alert in alerts if is_enforceable(alert)]


def blocked_result(message: Mapping[str, Any], triggers: list[Alert]) -> dict[str, Any]:
    """Protocol error naming the detector(s); upstream content is never copied."""
    return {
        "jsonrpc": message.get("jsonrpc", "2.0"),
        "id": message.get("id"),
        "error": {
            "code": BLOCKED_ERROR_CODE,
            "message": BLOCKED_MESSAGE,
            "data": {
                "policy_source": POLICY_SOURCE,
                "action": "blocked",
                "detectors": sorted({alert.detector for alert in triggers}),
                "categories": sorted({str(alert.details.get("category", "unknown")) for alert in triggers}),
            },
        },
    }


def _tool_name(tool: object) -> str:
    name = tool.get("name") if isinstance(tool, dict) else None
    return name if isinstance(name, str) and name else "unknown"


def _enforce_tool_catalog(message: dict[str, Any], tools: list[Any], inspector: _TextDetector) -> InjectionOutcome:
    kept: list[Any] = []
    alerts: list[Alert] = []
    withheld: set[str] = set()
    clean: set[str] = set()
    for tool in tools:
        name = _tool_name(tool)
        tool_alerts, failed = _scan(tool, name, inspector, None)
        alerts.extend(tool_alerts)
        triggers = _triggers(tool_alerts, failed)
        for alert in triggers:
            alert.action = "stripped"
        if triggers:
            withheld.add(name)
        else:
            kept.append(tool)
            clean.add(name)
    if not withheld:
        return InjectionOutcome(message, alerts, clean_tools=frozenset(clean))
    stripped = {**message, "result": {**message["result"], "tools": kept}}
    return InjectionOutcome(stripped, alerts, withheld_tools=frozenset(withheld), clean_tools=frozenset(clean - withheld))


def inspect_server_result(
    message: dict[str, Any],
    *,
    tool_name: str,
    tools_list: bool,
    mode: str,
    inspector: _TextDetector,
    vector: _VectorDetector | None = None,
) -> InjectionOutcome:
    """Detect injection in ``result``; in enforce mode strip poisoned tools or block the result.

    Detector errors fail open with an alert in ``alert`` mode and fail closed
    for the affected tool or result in ``enforce`` mode.
    """
    if "result" not in message:
        return InjectionOutcome(message, [])
    result = message.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if mode == "enforce" and tools_list and isinstance(tools, list):
        return _enforce_tool_catalog(message, tools, inspector)
    alerts, failed = _scan(result, tool_name, inspector, vector)
    if mode != "enforce":
        return InjectionOutcome(message, alerts)
    triggers = _triggers(alerts, failed)
    if not triggers:
        return InjectionOutcome(message, alerts)
    for alert in triggers:
        alert.action = "blocked"
    return InjectionOutcome(blocked_result(message, triggers), alerts, blocked=True)


def unparsed_output_alert(size: int) -> Alert:
    """Enforce mode dropped upstream stdout that was not JSON-RPC; the bytes themselves are never recorded."""
    return Alert(
        detector=POLICY_SOURCE,
        severity=AlertSeverity.MEDIUM,
        message="Dropped non-JSON-RPC upstream stdout in enforce mode",
        details={"category": "unparsed_stdout", "bytes": int(size)},
        action="blocked",
    )


def withheld_tool_call_alert(tool_name: str) -> Alert:
    return Alert(
        detector=POLICY_SOURCE,
        severity=AlertSeverity.HIGH,
        message=f"Blocked call to tool '{tool_name}' withheld for a poisoned description",
        details={"tool": tool_name, "category": "withheld_tool"},
        action="blocked",
    )
