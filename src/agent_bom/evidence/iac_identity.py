"""Occurrence identity retained across IaC projections and path redaction."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from uuid import UUID

from agent_bom.canonical_ids import canonical_id
from agent_bom.security import sanitize_text


def recorded_occurrence_id(value: Any) -> str | None:
    """Only opaque canonical UUIDs may survive as recorded occurrence keys."""
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return str(parsed) if parsed.version == 5 else None


def iac_occurrence_id(hit: dict[str, Any]) -> str:
    """Use the same normalized identity as the unified IaC Finding converter."""
    rule = sanitize_text(str(hit.get("rule_id") or "unknown"), max_len=80)
    path = sanitize_text(str(hit.get("file_path") or "unknown"), max_len=400)
    try:
        line = int(hit.get("line_number") or 0)
    except (TypeError, ValueError):
        line = 0
    title = sanitize_text(str(hit.get("title") or rule), max_len=300)
    message = sanitize_text(str(hit.get("message") or ""), max_len=600)
    return canonical_id("iac", rule, path, str(line), title, message)


def _coordinate(hit: dict[str, Any]) -> tuple[str, str, str]:
    return str(hit.get("rule_id") or "unknown"), str(hit.get("file_path") or "unknown"), str(hit.get("line_number") or 0)


def prepare_iac_occurrences(report: dict[str, Any]) -> dict[str, Any]:
    """Copy the IaC sections and align unambiguous legacy references.

    No historical graph or input row is mutated. Complete raw hits get a key
    before paths disappear; legacy rows join by exact id first, then only by a
    unique coordinate. Ambiguous legacy evidence remains unresolved.
    """
    section = report.get("iac_findings")
    if not isinstance(section, dict):
        return report
    hits = section.get("findings")
    if not isinstance(hits, list):
        return report
    by_coordinate: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    ids: set[str] = set()
    prepared: list[Any] = []
    for hit in hits:
        if not isinstance(hit, dict) or not hit.get("rule_id"):
            prepared.append(hit)
            continue
        hit_occurrence = recorded_occurrence_id(hit.get("occurrence_id")) or iac_occurrence_id(hit)
        prepared.append({**hit, "occurrence_id": hit_occurrence})
        by_coordinate[_coordinate(hit)].add(hit_occurrence)
        ids.add(hit_occurrence)
    if not ids:
        return report
    result = {**report, "iac_findings": {**section, "findings": prepared}}
    rows = report.get("findings")
    if not isinstance(rows, list):
        return result
    updated: list[Any] = []
    for row in rows:
        evidence = row.get("evidence") if isinstance(row, dict) else None
        if not isinstance(evidence, dict) or not evidence.get("iac"):
            updated.append(row)
            continue
        occurrence = recorded_occurrence_id(evidence.get("occurrence_id"))
        if occurrence not in ids:
            occurrence = row.get("id") if isinstance(row.get("id"), str) and row["id"] in ids else None
        candidates = by_coordinate[_coordinate(evidence)]
        if occurrence is None and len(candidates) == 1:
            occurrence = next(iter(candidates))
        legacy = "misconfig:iac:" + ":".join(_coordinate(evidence))
        if occurrence and row.get("finding_node_id") in (None, "", legacy, f"misconfig:iac:{occurrence}"):
            updated.append({**row, "finding_node_id": f"misconfig:iac:{occurrence}", "evidence": {**evidence, "occurrence_id": occurrence}})
        else:
            updated.append(row)
    result["findings"] = updated
    return result
