"""Trace explorer payload builder — runtime events joined to findings (#3608).

Fuses gateway/proxy feed events and runtime observations into a Langfuse-style
session tree where each tool-call span links to correlated findings (CVE,
compliance controls, policy block reason).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping, Sequence


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def correlate_findings(
    *,
    agent: str,
    tool: str,
    findings: Sequence[Mapping[str, Any]],
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return name-based candidates; these do not establish an inventory join."""
    agent_key = _norm(agent)
    tool_key = _norm(tool)
    if not agent_key and not tool_key:
        return []

    matched: list[dict[str, Any]] = []
    for row in findings:
        if not isinstance(row, Mapping):
            continue
        agents = {_norm(a) for a in (row.get("affected_agents") or []) if _norm(a)}
        tools: set[str] = set()
        for key in ("exposed_tools", "reachable_tools", "phantom_tools"):
            tools.update(_norm(t) for t in (row.get(key) or []) if _norm(t))
        if agent_key and agents and agent_key not in agents:
            continue
        if tool_key and tools and tool_key not in tools:
            continue
        if not agents and not tools:
            continue
        matched.append(
            {
                "correlation_basis": "candidate_name",
                "finding_id": row.get("id") or row.get("vulnerability_id"),
                "vulnerability_id": row.get("vulnerability_id") or row.get("cve_id"),
                "severity": row.get("severity"),
                "risk_score": row.get("risk_score"),
                "effective_reach_band": row.get("effective_reach_band"),
                "framework_tags": row.get("framework_tags") or [],
                "runtime_evidence": row.get("runtime_evidence"),
                "policy_state": (row.get("runtime_evidence") or {}).get("state"),
            }
        )
        if len(matched) >= limit:
            break
    return matched


def _span_from_feed_event(event: Mapping[str, Any], *, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    action = str(event.get("action_type") or "")
    agent = str(event.get("agent") or "")
    tool = str(event.get("target") or "")
    blocked = action == "tool_call_blocked"
    return {
        "span_id": f"{event.get('ts')}:{agent}:{tool}",
        "timestamp": event.get("ts"),
        "agent": agent,
        "tool": tool,
        "action_type": action,
        "verdict": "blocked" if blocked else ("observed" if action == "tool_call_authorized" else action),
        "detail": event.get("detail"),
        "shadow": bool(event.get("shadow")),
        "source": event.get("source"),
        "linked_findings": correlate_findings(agent=agent, tool=tool, findings=findings),
        "compliance_controls": sorted(
            {
                tag
                for finding in correlate_findings(agent=agent, tool=tool, findings=findings, limit=8)
                for tag in (finding.get("framework_tags") or [])
            }
        ),
    }


def _span_from_observation(obs: Mapping[str, Any], *, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    agent = str(obs.get("agent_name") or "")
    tool = str(obs.get("tool_name") or "")
    verdict = str(obs.get("verdict") or "observed")
    metadata = obs.get("metadata") or {}
    imported = obs.get("surface") == "imported_trace"
    # Native provider names are not inventory identifiers. Without a verified
    # inventory mapping imported spans remain unlinked, even on an exact name.
    linked = [] if imported else correlate_findings(agent=agent, tool=tool, findings=findings)
    return {
        "surface": str(obs.get("surface") or "runtime"),
        "parent_span_id": str(metadata.get("parent_observation_id") or ""),
        "logical_root": metadata.get("logical_root"),
        "native_type": str(metadata.get("native_type") or ""),
        "native_name": str(metadata.get("native_name") or ""),
        "event_time_missing": bool(metadata.get("event_time_missing")),
        "collected_at": metadata.get("collected_at"),
        "end_time_unix_nano": metadata.get("end_time_unix_nano"),
        "correlation_state": "unmapped" if imported else "candidate_name" if linked else "unmatched",
        "source_scope": {
            key: str(metadata.get(key) or "") for key in ("provider", "connection_id", "project_id", "environment", "account_id")
        },
        "span_id": str(obs.get("observation_id") or obs.get("span_id") or ""),
        "timestamp": obs.get("observed_at"),
        "agent": agent,
        "tool": tool,
        "action_type": str(obs.get("event_type") or "runtime_observation"),
        "verdict": verdict,
        "detail": str((obs.get("summary") or {}).get("message") or obs.get("event_type") or ""),
        "shadow": False,
        "source": obs.get("source") or "runtime_store",
        "trace_id": obs.get("trace_id"),
        "session_id": obs.get("session_id"),
        "linked_findings": linked,
        "compliance_controls": sorted({tag for finding in linked for tag in (finding.get("framework_tags") or [])}),
    }


def build_trace_explorer_payload(
    *,
    tenant_id: str,
    feed_events: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    sessions: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    limit: int = 100,
    inventory_bindings: Mapping[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build session-grouped trace explorer tree for the UI."""
    session_map: dict[str, dict[str, Any]] = {}

    def _ensure_session(session_id: str, *, agent: str = "", trace_id: str = "") -> dict[str, Any]:
        if session_id not in session_map:
            session_map[session_id] = {
                "session_id": session_id,
                "agent": agent,
                "trace_id": trace_id,
                "spans": [],
                "blocked_count": 0,
                "observed_count": 0,
            }
        return session_map[session_id]

    for event in feed_events[:limit]:
        agent = str(event.get("agent") or "unknown")
        session_id = f"feed:{agent}"
        session = _ensure_session(session_id, agent=agent)
        span = _span_from_feed_event(event, findings=findings)
        session["spans"].append(span)
        if span["verdict"] == "blocked":
            session["blocked_count"] += 1
        else:
            session["observed_count"] += 1

    for obs in observations[:limit]:
        if obs.get("tenant_id") not in (None, tenant_id):
            continue
        session_id = str(obs.get("session_id") or f"obs:{obs.get('trace_id') or obs.get('agent_name') or 'unknown'}")
        session = _ensure_session(
            session_id,
            agent=str(obs.get("agent_name") or ""),
            trace_id=str(obs.get("trace_id") or ""),
        )
        span = _span_from_observation(obs, findings=findings)
        binding = (inventory_bindings or {}).get(str(obs.get("observation_id") or ""))
        if binding:
            span["inventory_binding"] = binding
            span["correlation_state"] = binding["state"]
        session["spans"].append(span)
        if span["verdict"] == "blocked":
            session["blocked_count"] += 1
        else:
            session["observed_count"] += 1

    _merge_session_metadata(sessions, tenant_id, _ensure_session)

    for session in session_map.values():
        session["spans"].sort(key=lambda span: str(span.get("timestamp") or ""))
        session["spans"] = _ordered_native_spans(session["spans"])

    sessions_out = sorted(session_map.values(), key=lambda row: str(row.get("last_seen") or row.get("session_id")), reverse=True)

    total_blocked = sum(int(s.get("blocked_count") or 0) for s in sessions_out)
    total_spans = sum(len(s.get("spans") or []) for s in sessions_out)

    return {
        "schema_version": "runtime.trace_explorer.v1",
        "tenant_id": tenant_id,
        "session_count": len(sessions_out),
        "span_count": total_spans,
        "blocked_count": total_blocked,
        "sessions": sessions_out,
    }


__all__ = ["build_trace_explorer_payload", "correlate_findings"]


def _ordered_native_spans(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bounded physical-parent projection, never repair missing or cyclic links.

    Missing means absent from this response, not absent at the provider. A
    logical root can retain a physical parent. Imported observation IDs already
    include connection/project/environment scope; session grouping adds a guard.
    """
    nodes = {span["span_id"]: span for span in spans}
    for span in spans:
        seen = {span["span_id"]}
        parent = span.get("parent_span_id", "")
        depth = 0
        state = "root" if not parent else "resolved"
        while parent:
            if parent in seen:
                state, depth = "cycle", 0
                break
            seen.add(parent)
            ancestor = nodes.get(parent)
            if ancestor is None:
                if depth == 0:
                    state = "missing"
                break
            depth += 1
            parent = ancestor.get("parent_span_id", "")
        span.update(parent_state=state, depth=depth)
    children: dict[str, list[dict[str, Any]]] = {}
    roots = []
    for span in spans:
        parent = span.get("parent_span_id", "")
        if span["parent_state"] == "resolved" and parent in nodes:
            children.setdefault(parent, []).append(span)
        else:
            roots.append(span)
    ordered = []
    pending = list(reversed(roots))
    while pending:
        span = pending.pop()
        ordered.append(span)
        pending.extend(reversed(children.get(span["span_id"], [])))
    return ordered


def _merge_session_metadata(
    sessions: Sequence[Mapping[str, Any]],
    tenant_id: str,
    ensure_session: Callable[..., dict[str, Any]],
) -> None:
    for raw_session in sessions:
        if raw_session.get("tenant_id") not in (None, tenant_id):
            continue
        session_id = str(raw_session.get("session_id") or "")
        if not session_id:
            continue
        session = ensure_session(
            session_id,
            agent=str(raw_session.get("agent_name") or ""),
            trace_id=str(raw_session.get("trace_id") or ""),
        )
        session.setdefault("first_seen", raw_session.get("first_seen"))
        session.setdefault("last_seen", raw_session.get("last_seen"))
        session.setdefault("observation_count", raw_session.get("observation_count"))
