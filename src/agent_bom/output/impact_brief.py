"""Bounded, deterministic leadership views of retained scan evidence.

No discovery, authority inference, name matching or remediation verification is
performed here. Source digests bind canonical JSON, not an authenticated author.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from agent_bom.core.severity import severity_band_rank
from agent_bom.security import sanitize_sensitive_payload

MAX_BYTES = 20_000_000
MAX_ROWS = 20_000
BOUNDARY = (
    "Recorded relationships describe potential exposure, not proof of execution, effective access or exploitation. "
    "Framework mappings are context, not attack evidence. Counts apply only to these supplied scan records."
)


def _encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _identity(value: Any, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 1024 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid identity")
    if "redacted" in value.lower() or value == "[truncated]":
        if required:
            raise ValueError("unavailable identity")
        return None
    return value


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_ROWS or any(not isinstance(row, dict) for row in value):
        raise ValueError("invalid or oversized row collection")
    return value


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing observation time")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("observation time needs a timezone")
    return stamp


def _index(rows: list[dict[str, Any]], *, finding_aliases: bool = True) -> dict[str, tuple[int, dict[str, Any]]]:
    result: dict[str, tuple[int, dict[str, Any]]] = {}
    for position, row in enumerate(rows):
        identifier = _identity(row.get("id"), required=True)
        assert identifier is not None
        for key in ("occurrence_id", "canonical_id", "finding_id") if finding_aliases else ():
            if row.get(key) is not None and _identity(row[key], required=True) != identifier:
                raise ValueError("conflicting row identity")
        if identifier in result and result[identifier][1] != row:
            raise ValueError("conflicting duplicate identity")
        result.setdefault(identifier, (position, row))
    return result


def _asset(row: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    asset = row.get("asset") or {}
    if not isinstance(asset, dict):
        raise ValueError("invalid asset")
    canonical, stable = _identity(asset.get("canonical_id")), _identity(asset.get("stable_id"))
    if canonical and stable and canonical != stable:
        raise ValueError("conflicting asset identity")
    return canonical or stable, asset


def _agents(row: dict[str, Any]) -> set[str]:
    evidence = row.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise ValueError("invalid evidence")
    links = _rows(evidence.get("agent_server_links", []))
    return {identifier for link in links if (identifier := _identity(link.get("agent_ref")))}


def _coverage(doc: dict[str, Any]) -> dict[str, Any]:
    run = doc.get("scan_run") or {}
    if not isinstance(run, dict):
        raise ValueError("invalid scan execution evidence")
    return {
        "outcome": run.get("outcome", "unknown"),
        "scopes": _rows(run.get("scopes", [])),
        "issues": _rows(run.get("issues", [])),
        "warnings": {"coverage": doc.get("coverage_warnings", []), "scan": doc.get("warnings", [])},
    }


def _priority(identifier: str, position: int, row: dict[str, Any]) -> dict[str, Any]:
    asset_id, asset = _asset(row)
    return {
        "id": identifier,
        "title": row.get("title") or "Untitled finding",
        "severity": row.get("severity", "unknown"),
        "asset_id": asset_id,
        "asset_name": asset.get("name") or "Unspecified asset",
        "agent_ids": sorted(_agents(row)),
        "reported_condition": row.get("description") or "Not recorded",
        "potential_consequence": (
            "Business impact and exploitation are not established by this summary; review applicability and path evidence."
        ),
        "confidence_basis": row.get("match_confidence_tier") or "Not recorded; no confidence inferred",
        "recommended_action": row.get("remediation_guidance") or "Review the source evidence and assign an owner before choosing a change.",
        "owner": row.get("owner") or "Unassigned",
        "receipt_pointer": f"/findings/{position}",
        "receipt": _bounded_receipt(row),
    }


def _bounded_receipt(row: dict[str, Any]) -> dict[str, Any]:
    encoded = _encoded(row)
    if len(encoded) <= 64_000:
        return row
    return {
        "detail_omitted": True,
        "reason": "Source row exceeds 64 KB; inspect the retained input at the JSON pointer.",
        "source_row_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _counts(rows: list[dict[str, Any]], indexed: dict[str, tuple[int, dict[str, Any]]], paths: Any) -> dict[str, Any]:
    assets: dict[str, dict[str, Any]] = {}
    agents: set[str] = set()
    groups: set[str] = set()
    missing = {"occurrences_without_asset_id": 0, "occurrences_without_agent_id": 0, "occurrences_without_group_id": 0}
    for _, row in indexed.values():
        asset_id, asset = _asset(row)
        if asset_id and asset_id in assets and assets[asset_id] != asset:
            raise ValueError("conflicting asset records")
        if asset_id:
            assets[asset_id] = asset
        linked = _agents(row)
        agents.update(linked)
        group_id = _identity(row.get("finding_group_id"))
        if group_id:
            groups.add(group_id)
        missing["occurrences_without_asset_id"] += int(asset_id is None)
        missing["occurrences_without_agent_id"] += int(not linked)
        missing["occurrences_without_group_id"] += int(group_id is None)
    path_count = None if paths is None else len(_index(_rows(paths), finding_aliases=False))
    return {
        "finding_rows": len(rows),
        "finding_occurrences": len(indexed),
        "finding_groups": len(groups),
        "asset_ids": len(assets),
        "agent_ids": len(agents),
        "recorded_paths": path_count,
        **missing,
    }


def _snapshot(doc: dict[str, Any], limit: int) -> tuple[dict[str, Any], dict[str, tuple[int, dict[str, Any]]]]:
    encoded = _encoded(doc)
    if len(encoded) > MAX_BYTES or doc.get("document_type") != "AI-BOM" or doc.get("schema_version") != "1.0":
        raise ValueError("unsupported scan report or size")
    scan_id = _identity(doc.get("scan_id"), required=True)
    _time(doc.get("generated_at"))
    tenant = _identity(doc.get("tenant_id"), required=doc.get("tenant_id") is not None)
    identity_schema = _identity(doc.get("canonical_id_schema_version"))
    sources = doc.get("scan_sources", [])
    if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
        raise ValueError("invalid scan source labels")
    rows = _rows(doc.get("findings"))
    indexed = _index(rows)
    exposure = doc.get("exposure_paths") or {}
    if not isinstance(exposure, dict):
        raise ValueError("invalid path collection")
    counts = _counts(rows, indexed, exposure.get("paths"))
    ranked = sorted(indexed.items(), key=lambda item: (severity_band_rank(str(item[1][1].get("severity", "unknown"))), item[0]))
    paths = _index(_rows(exposure.get("paths", [])), finding_aliases=False)
    return {
        "scan_id": scan_id,
        "generated_at": doc["generated_at"],
        "source_sha256": hashlib.sha256(encoded).hexdigest(),
        "tenant_id": tenant,
        "canonical_id_schema_version": identity_schema,
        "scan_sources": sources,
        "coverage": _coverage(doc),
        "counts": counts,
        "priorities": [_priority(identifier, position, row) for identifier, (position, row) in ranked[:limit]],
        "omitted_occurrences": max(0, len(indexed) - limit),
        "paths": [
            {"id": identifier, "receipt_pointer": f"/exposure_paths/paths/{position}", "receipt": _bounded_receipt(row)}
            for identifier, (position, row) in sorted(paths.items())[:limit]
        ],
        "omitted_paths": max(0, len(paths) - limit),
    }, indexed


def _recorded_scope(snapshot: dict[str, Any]) -> list[str] | None:
    coverage = snapshot["coverage"]
    scopes = coverage["scopes"]
    if coverage["outcome"] != "complete" or not scopes or any(coverage["warnings"].values()):
        return None
    if any(issue.get("affects_coverage", True) for issue in coverage["issues"]):
        return None
    if any(scope.get("requested") is not True or scope.get("status") != "complete" for scope in scopes):
        return None
    names = [_identity(scope.get("name"), required=True) for scope in scopes]
    if len(set(names)) != len(names):
        return None
    return sorted(str(name) for name in names)


def _comparison(before: dict[str, Any], after: dict[str, Any], old: dict, new: dict, limit: int) -> dict[str, Any]:
    if before["scan_id"] == after["scan_id"] or _time(before["generated_at"]) >= _time(after["generated_at"]):
        raise ValueError("comparison needs distinct ordered snapshots")
    for key in ("tenant_id", "canonical_id_schema_version"):
        if before[key] != after[key]:
            raise ValueError("incompatible comparison identity scope")
    if not after["canonical_id_schema_version"]:
        raise ValueError("comparison identity scheme is unknown")
    previous_scope, current_scope = _recorded_scope(before), _recorded_scope(after)
    matching = bool(
        current_scope and previous_scope == current_scope and before["scan_sources"] and before["scan_sources"] == after["scan_sources"]
    )
    changes = {
        "newly_recorded": sorted(new.keys() - old.keys()),
        "not_observed": sorted(old.keys() - new.keys()),
        "changed": sorted(key for key in old.keys() & new.keys() if old[key][1] != new[key][1]),
        "retained": sorted(old.keys() & new.keys()),
    }
    return {
        **{key: ids[:limit] for key, ids in changes.items()},
        "counts": {key: len(ids) for key, ids in changes.items()},
        "detail_limit": limit,
        "receipts": _change_receipts(changes, old, new, limit),
        "scope_status": "matching_recorded_scope" if matching else "unverified",
        "verified_fixes": None,
        "claim_boundary": (
            "A record not observed in the later input is not proof of a verified fix. Matching scope labels do not authenticate coverage."
        ),
    }


def _change_receipts(changes: dict[str, list[str]], old: dict, new: dict, limit: int) -> list[dict[str, Any]]:
    receipts = []
    for change in ("newly_recorded", "not_observed", "changed"):
        for identifier in changes[change][:limit]:
            receipt: dict[str, Any] = {"change": change, "id": identifier}
            for name, rows in (("before", old), ("after", new)):
                if identifier in rows:
                    position, row = rows[identifier]
                    receipt[f"{name}_pointer"] = f"/findings/{position}"
                    receipt[name] = _bounded_receipt(row)
            receipts.append(receipt)
    return receipts


def _restore_pointers(raw: dict[str, Any], clean: dict[str, Any]) -> None:
    # Only restore pointers generated from integer array positions, never fields
    # inside the untrusted receipt itself.
    for name in ("current", "baseline"):
        if raw[name] is not None:
            for collection in ("priorities", "paths"):
                for source, dest in zip(raw[name][collection], clean[name][collection], strict=True):
                    dest["receipt_pointer"] = source["receipt_pointer"]
    if raw["comparison"]:
        for source, dest in zip(raw["comparison"]["receipts"], clean["comparison"]["receipts"], strict=True):
            for key in ("before_pointer", "after_pointer"):
                if key in source:
                    dest[key] = source[key]


def build_impact_brief(current: dict[str, Any], *, before: dict[str, Any] | None = None, limit: int = 10) -> dict[str, Any]:
    """Summarize exact record identities before redaction; bound expanded detail.

    The brief retains sanitized source rows with JSON pointers. Digests use
    sorted compact ASCII JSON. Removed records never become verified fixes.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("detail limit must be between 1 and 50")
    candidate, new = _snapshot(current, limit)
    baseline, old = _snapshot(before, limit) if before is not None else (None, {})
    result = {
        "schema_version": "1",
        "claim_boundary": BOUNDARY,
        "current": candidate,
        "baseline": baseline,
        "comparison": _comparison(baseline, candidate, old, new, limit) if baseline else None,
        "limitations": [
            "Asset and agent totals count explicit IDs, not names or proven physical instances. Missing IDs are reported separately.",
            "Agent IDs come only from recorded agent_server_links; no path traversal or label matching is performed.",
            "Recorded path counts are independent of finding occurrences; absent path evidence is unknown, not zero.",
            "Source rows are redacted and strings are bounded to 4000 characters. Keep original inputs privately for full receipts.",
            "SHA-256 identifies canonical source content; it does not authenticate the producer or prove collection completeness.",
            "This local report does not close findings, change deployments, publish data or send telemetry.",
        ],
    }
    clean = sanitize_sensitive_payload(result, max_str_len=4000)
    assert isinstance(clean, dict)
    # JSON pointers are generated exclusively from validated integer positions;
    # filesystem redaction must not turn them into unrelated path placeholders.
    _restore_pointers(result, clean)
    return clean
