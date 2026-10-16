"""Preserve competing security assertions when observations of one asset merge.

The projection retains a positive risk flag, not a claim of current exposure.
Receipts retain the source snapshot and node so a later review can resolve the
disagreement. A merged projection is never attributed to its individual sources.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.cloud.normalization import coerce_bool_or_none

SECURITY_ASSERTIONS = frozenset(
    {
        "admin_equivalent",
        "internet_exposed",
        "internet_facing",
        "is_public",
        "on_attack_path",
        "public",
        "public_access",
        "publicly_accessible",
        "toxic_exposed_sensitive",
        "toxic_exposed_vulnerable",
    }
)


def prior_security_assertions(attributes: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Read bounded-field assertion receipts, tolerating older snapshot shapes."""
    result: dict[str, list[dict[str, Any]]] = {}
    for name in ("identity", "correlation"):
        receipt = attributes.get(name)
        conflicts = receipt.get("conflicts") if isinstance(receipt, Mapping) else None
        if not isinstance(conflicts, Mapping):
            continue
        for field in SECURITY_ASSERTIONS.intersection(conflicts):
            entries = conflicts[field]
            if isinstance(entries, list):
                result.setdefault(field, []).extend(dict(entry) for entry in entries if isinstance(entry, Mapping) and "value" in entry)
    return result


def resolve_security_assertions(
    observations: Iterable[tuple[str, str, str, Mapping[str, Any]]], merged: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """Merge (source, scan id, node id, attributes) without losing positive risk.

    Only boolean security fields get competing-value receipts. Unknown provider
    values remain unknown; arbitrary attribute strings are not copied into them.
    Prior receipts replace the synthetic projection when an asset is re-merged.
    """
    records: dict[str, dict[str, dict[str, Any]]] = {}
    for source, scan_id, node_id, attributes in observations:
        prior = prior_security_assertions(attributes)
        for field in SECURITY_ASSERTIONS.intersection(attributes) | prior.keys():
            entries = prior.get(field)
            if not entries:
                value = attributes.get(field)
                if value is None or value == "":
                    continue
                entries = [{"value": coerce_bool_or_none(value), "source": source, "scan_id": scan_id, "node_id": node_id}]
            for entry in entries:
                normalized: dict[str, Any] = {"value": coerce_bool_or_none(entry["value"])}
                normalized.update({key: str(entry.get(key, "")) for key in ("source", "scan_id", "node_id")})
                key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
                records.setdefault(field, {})[key] = normalized
    conflicts: dict[str, list[dict[str, Any]]] = {}
    for field, values in sorted(records.items()):
        entries = [values[key] for key in sorted(values)]
        if len({entry["value"] for entry in entries}) < 2:
            continue
        conflicts[field] = entries
        if any(entry["value"] is True for entry in entries):
            merged[field] = True
    return conflicts
