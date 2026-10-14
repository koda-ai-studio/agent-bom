"""Per-occurrence applicability of a vulnerability: reachability plus VEX.

One CVE node is shared by every asset that carries it, but whether it is
reachable, and whether a VEX statement rules it out, is a fact about one
occurrence (asset -> CVE). Producers record that fact on the primary
``vulnerable_to`` edge as ``evidence["applicability"]``; path derivation reads
it there. The CVE node keeps an order-independent aggregate for display.

Edges written before applicability existed fall back to the CVE node's
attributes, so older snapshots keep their behaviour.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from agent_bom.core.reachability import node_reachability

#: VEX statuses that rule an occurrence out of attack paths.
SUPPRESSING_VEX_STATUSES = frozenset({"not_affected", "fixed"})
_VERDICT_STRENGTH = {"confirmed": 3, "likely": 2, "unknown": 1, "unlikely": 0}
_REACHABILITY_FIELDS = ("graph_reachable", "symbol_reachability", "dependency_reachable")


@dataclass(frozen=True, slots=True)
class Applicability:
    verdict: str
    basis: tuple[str, ...]
    vex_status: str | None = None
    vex_justification: str | None = None

    @property
    def vex_excluded(self) -> bool:
        return self.vex_status in SUPPRESSING_VEX_STATUSES

    @property
    def unlikely(self) -> bool:
        return self.verdict == "unlikely"

    @property
    def permits_exploit_chain(self) -> bool:
        return self.verdict in {"confirmed", "likely"} and not self.vex_excluded


def _text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def applicability_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """The applicability evidence for one blast-radius / finding row."""
    reach = node_reachability(row)
    payload: dict[str, Any] = {"verdict": reach.verdict.value, "basis": list(reach.basis)}
    for key in _REACHABILITY_FIELDS:
        if row.get(key) is not None:
            payload[key] = row[key]
    for key in ("vex_status", "vex_justification"):
        value = _text(row.get(key))
        if value:
            payload[key] = value
    return payload


def row_finding_ids(row: dict[str, Any]) -> list[str]:
    """The Finding.id a report row projects (blast rows keep it as ``canonical_id``)."""
    value = _text(row.get("finding_id")) or _text(row.get("canonical_id"))
    return [value] if value else []


def applicability_from_payload(payload: dict[str, Any]) -> Applicability:
    verdict = str(payload.get("verdict") or "unknown")
    if verdict not in _VERDICT_STRENGTH:
        verdict = "unknown"
    basis = payload.get("basis")
    return Applicability(
        verdict=verdict,
        basis=tuple(str(item) for item in basis) if isinstance(basis, list) else (),
        vex_status=_text(payload.get("vex_status")),
        vex_justification=_text(payload.get("vex_justification")),
    )


def edge_applicability(edge: Any, vulnerability_attributes: dict[str, Any] | None) -> Applicability:
    """The occurrence's applicability; legacy edges read the CVE node."""
    payload = (getattr(edge, "evidence", None) or {}).get("applicability") if edge is not None else None
    if isinstance(payload, dict):
        return applicability_from_payload(payload)
    attrs = vulnerability_attributes or {}
    reach = node_reachability(attrs)
    return Applicability(
        verdict=reach.verdict.value,
        basis=reach.basis,
        vex_status=_text(attrs.get("vex_status")),
        vex_justification=_text(attrs.get("vex_justification")),
    )


def stronger_applicability(current: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    """Combine two rows landing on one edge without dropping an exploitable one."""
    if not isinstance(current, dict):
        return incoming
    left, right = applicability_from_payload(current), applicability_from_payload(incoming)
    if _VERDICT_STRENGTH[right.verdict] != _VERDICT_STRENGTH[left.verdict]:
        return incoming if _VERDICT_STRENGTH[right.verdict] > _VERDICT_STRENGTH[left.verdict] else current
    return current if not left.vex_excluded or right.vex_excluded else incoming


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """CVE-node attributes summarising every occurrence, independent of row order."""
    payloads = [applicability_from_row(row) for row in rows]
    ranked = sorted(
        range(len(rows)),
        key=lambda index: (
            -_VERDICT_STRENGTH.get(payloads[index]["verdict"], 1),
            applicability_from_payload(payloads[index]).vex_excluded,
            index,
        ),
    )
    strongest = rows[ranked[0]]
    vex = [payload.get("vex_status") for payload in payloads]
    common_vex = vex[0] if vex and all(value == vex[0] for value in vex) else None
    justifications = {payload.get("vex_justification") for payload in payloads}

    def union(key: str) -> int:
        return len({str(item) for row in rows for item in (row.get(key) or [])})

    attributes: dict[str, Any] = {
        "affected_agent_count": union("affected_agents"),
        "affected_server_count": union("affected_servers"),
        "exposed_credential_count": union("exposed_credentials"),
        "exposed_tool_count": union("exposed_tools"),
        "reachability": payloads[ranked[0]]["verdict"],
        "reachability_basis": list(payloads[ranked[0]]["basis"]),
        "graph_reachable": strongest.get("graph_reachable"),
        "symbol_reachability": strongest.get("symbol_reachability"),
        "symbol_reachability_reason": strongest.get("symbol_reachability_reason"),
        "runtime_dependency_chain": list(strongest.get("runtime_dependency_chain") or []),
        "dependency_reachable": strongest.get("dependency_reachable"),
        "actionable": any(bool(row.get("actionable")) for row in rows),
        "occurrence_verdicts": dict(sorted(Counter(payload["verdict"] for payload in payloads).items())),
        "vex_status": common_vex,
        "vex_justification": justifications.pop() if common_vex and len(justifications) == 1 else None,
    }
    if any(vex):
        attributes["occurrence_vex"] = dict(sorted(Counter(value or "none" for value in vex).items()))
    return attributes
