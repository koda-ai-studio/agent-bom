"""Unified findings derived from canonical trace events.

Screened signals (prompt injection, personal data, secrets), vulnerable tool
calls and shadow agents/tools become Finding rows in the tenant's compliance
hub, linked to the exact inventory node when the span reported one. Each
finding is deduplicated per tenant, signal, entity and UTC day. Evidence holds
counts, timestamps and trace identifiers only, never content.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_bom.canonical_ids import canonical_id
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.trace_projection import ShadowEntity
from agent_bom.runtime.normalized_trace import NormalizedTraceEvent
from agent_bom.security import sanitize_text

_logger = logging.getLogger(__name__)
FindingSink = Callable[[str, list[dict[str, Any]]], int]
_SAMPLE = 5


@dataclass(frozen=True)
class _Spec:
    finding_type: FindingType
    severity: str
    title: str
    owasp: tuple[str, ...]
    owasp_mcp: tuple[str, ...]
    owasp_agentic: tuple[str, ...]
    nist_ai_rmf: tuple[str, ...]
    remediation: str


_SPECS: dict[str, _Spec] = {
    "prompt_injection": _Spec(
        FindingType.INJECTION,
        "high",
        "Prompt injection observed in runtime trace",
        ("LLM01",),
        ("MCP06", "MCP10"),
        ("ASI01",),
        ("MEASURE-2.7", "MANAGE-4.1"),
        "Review the traced inputs to this agent or tool and enforce input screening at the gateway.",
    ),
    "pii": _Spec(
        FindingType.PII_EXPOSURE,
        "medium",
        "Personal data observed in runtime trace",
        ("LLM02",),
        ("MCP10",),
        (),
        ("MEASURE-2.7", "MANAGE-4.1"),
        "Confirm whether this agent should handle personal data and enable redaction before content leaves it.",
    ),
    "secret": _Spec(
        FindingType.CREDENTIAL_EXPOSURE,
        "high",
        "Credential observed in runtime trace content",
        ("LLM02",),
        ("MCP01",),
        ("ASI03",),
        ("MEASURE-2.7", "MANAGE-4.1"),
        "Rotate the exposed credential and stop the agent or tool from echoing secrets into model or trace content.",
    ),
    "vulnerable_tool_call": _Spec(
        FindingType.COMBINATION,
        "high",
        "Vulnerable tool exercised at runtime",
        ("LLM03",),
        ("MCP04",),
        ("ASI04",),
        ("MAP-4.1", "MANAGE-4.1"),
        "Upgrade the vulnerable package behind this tool; runtime traces show it is being called.",
    ),
}
_SHADOW = _Spec(
    FindingType.SHADOW_AI,
    "medium",
    "Unlisted {kind} observed at runtime",
    ("LLM06",),
    ("MCP09",),
    ("ASI10",),
    ("GOVERN-1.5", "MANAGE-4.1"),
    "Inventory this {kind} (scan its configuration) or block it; traces show it running without an inventory record.",
)


@dataclass
class _Group:
    events: list[NormalizedTraceEvent] = field(default_factory=list)


def _entity(event: NormalizedTraceEvent) -> tuple[str, str, str | None]:
    """``(asset_type, name, exact node id)`` for the span's own entity."""
    node_id = event.match_node_id if event.match_method == "exact" else event.agent_ref
    if event.kind == "tool" or event.tool_name:
        return "tool", event.tool_name or node_id or "unknown-tool", node_id
    return "agent", event.agent_name or node_id or "unknown-agent", node_id


def _day(moment: str) -> str:
    return moment[:10] if moment else datetime.now(timezone.utc).date().isoformat()


@dataclass(frozen=True)
class _Observed:
    count: int
    first_seen: str
    last_seen: str
    sources: tuple[str, ...]
    trace_ids: tuple[str, ...]

    @classmethod
    def of(cls, events: list[NormalizedTraceEvent]) -> _Observed:
        moments = sorted(event.started_at or "" for event in events)
        traces = sorted({event.source_trace_id for event in events if event.source_trace_id})
        return cls(len(events), moments[0], moments[-1], tuple(sorted({event.source for event in events})), tuple(traces[:_SAMPLE]))


def _finding(
    tenant_id: str,
    spec: _Spec,
    key: str,
    asset: Asset,
    node_id: str | None,
    seen: _Observed,
    extra: dict[str, Any],
    suffix: str = "",
) -> Finding:
    kind = asset.asset_type
    title = spec.title.format(kind=kind) + suffix
    evidence = {
        "trace_sources": list(seen.sources),
        "sample_trace_ids": list(seen.trace_ids),
        "count": seen.count,
        "first_seen": seen.first_seen,
        "last_seen": seen.last_seen,
        "match_method": "exact" if node_id else "none",
        "window_day": _day(seen.last_seen),
        **{name: value for name, value in extra.items() if value is not None},
    }
    return Finding(
        finding_type=spec.finding_type,
        source=FindingSource.PROXY,
        asset=asset,
        severity=extra.get("severity") or spec.severity,
        title=title,
        description=f"{title}: {asset.name} ({seen.count} span(s), {seen.first_seen} to {seen.last_seen}).",
        remediation_guidance=spec.remediation.format(kind=kind),
        owasp_tags=list(spec.owasp),
        owasp_mcp_tags=list(spec.owasp_mcp),
        owasp_agentic_tags=list(spec.owasp_agentic),
        nist_ai_rmf_tags=list(spec.nist_ai_rmf),
        evidence=evidence,
        node_id=node_id,
        first_seen=seen.first_seen or None,
        id=canonical_id("runtime_trace_finding", tenant_id, key, asset.identifier, evidence["window_day"]),
    )


def _asset(asset_type: str, name: str, node_id: str | None, source: str) -> Asset:
    name = sanitize_text(name, max_len=300)
    return Asset(name=name, asset_type=asset_type, identifier=node_id or f"runtime:{source}:{asset_type}:{name.lower()}")


def signal_findings(tenant_id: str, events: Iterable[NormalizedTraceEvent], *, severities: dict[str, str] | None = None) -> list[Finding]:
    """One finding per tenant, signal, entity and day across every span carrying that signal."""
    groups: dict[tuple[str, str, str, str | None, str], _Group] = {}
    for event in events:
        if event.tenant_id != tenant_id:
            continue
        asset_type, name, node_id = _entity(event)
        for signal in sorted(event.signals - {"vulnerable_tool_call"}):
            key = (signal, asset_type, name, node_id, _day(event.started_at or ""))
            groups.setdefault(key, _Group()).events.append(event)
    findings: list[Finding] = []
    for (signal, asset_type, name, node_id, _), group in sorted(groups.items(), key=lambda item: str(item[0])):
        asset = _asset(asset_type, name, node_id, group.events[0].source)
        extra = {"signal": signal, "severity": (severities or {}).get(signal)}
        findings.append(_finding(tenant_id, _SPECS[signal], signal, asset, node_id, _Observed.of(group.events), extra))
    return findings


def vulnerable_call_findings(tenant_id: str, flagged: Iterable[Any], events: Iterable[NormalizedTraceEvent]) -> list[Finding]:
    """One finding per tool, matched advisory and day for tool calls backed by a known-vulnerable package."""
    by_span = {(event.source_trace_id, event.source_span_id): event for event in events}
    groups: dict[tuple[str, str, str | None, str], _Group] = {}
    for flag in flagged:
        event = by_span.get((flag.trace.trace_id, flag.trace.span_id))
        if event is None or event.tenant_id != tenant_id:
            continue
        _, name, node_id = _entity(event)
        for cve in sorted({str(cve) for cve in flag.matched_cves if cve}) or [""]:
            groups.setdefault((cve, flag.trace.tool_name or name, node_id, _day(event.started_at or "")), _Group()).events.append(event)
    findings: list[Finding] = []
    for (cve, name, node_id, _), group in sorted(groups.items(), key=lambda item: str(item[0])):
        asset = _asset("tool", name, node_id, group.events[0].source)
        seen = _Observed.of(group.events)
        key = f"vulnerable_tool_call:{cve}"
        spec = _SPECS["vulnerable_tool_call"]
        findings.append(
            _finding(tenant_id, spec, key, asset, node_id, seen, {"signal": "vulnerable_tool_call"}, f" ({cve})" if cve else "")
        )
    return findings


def shadow_findings(tenant_id: str, shadow: Iterable[ShadowEntity]) -> list[Finding]:
    findings: list[Finding] = []
    for entity in shadow:
        asset = _asset(entity.kind, entity.name, None, entity.source)
        seen = _Observed(entity.count, entity.first_seen, entity.last_seen, (entity.source,), entity.sample_trace_ids)
        extra = {"signal": "shadow", "observed_under_agent": entity.agent_node_id}
        findings.append(_finding(tenant_id, _SHADOW, f"shadow:{entity.kind}", asset, None, seen, extra))
    return findings


def write_findings(tenant_id: str, findings: list[Finding], sink: FindingSink | None) -> int:
    """Hand findings to the tenant's finding store; an outage is logged and reported as zero written."""
    if not findings or sink is None:
        return 0
    try:
        return sink(tenant_id, [finding.to_dict() for finding in findings])
    except Exception:  # broad-except: a findings-store outage must not discard the trace ingest it annotates
        _logger.warning("Runtime trace findings were not persisted", exc_info=False)
        return 0
