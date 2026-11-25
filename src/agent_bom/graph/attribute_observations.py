"""Bounded, deterministic receipts for values merged into one graph node.

Receipts describe collector assertions, not independently verified truth. Source
names do not confer authority. The latest dated assertion wins; equal times use
positive boolean risk, then a stable value digest, and expose disagreement. Risk scoring remains separate.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol

from agent_bom.core.security_assertions import SECURITY_ASSERTIONS
from agent_bom.core.timestamps import parse_timestamp


class ObservedNode(Protocol):
    attributes: dict[str, Any]
    last_seen: str
    data_sources: list[str]
    _clock_defaulted: tuple[str, ...]


_RECEIPTS = "attribute_observations"
_EXCLUDED = {_RECEIPTS, "risk_assessment"}


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _receipt(node: ObservedNode, key: str) -> dict[str, Any]:
    value_digest = _digest(node.attributes[key])
    prior = node.attributes.get(_RECEIPTS)
    record = prior.get(key) if isinstance(prior, dict) else None
    # Attribute mutations invalidate old receipts instead of laundering freshness.
    if (
        isinstance(record, dict)
        and record.get("value_digest") == value_digest
        and (record.get("observed_at") is None or parse_timestamp(record.get("observed_at")) is not None)
        and isinstance(record.get("sources"), list)
        and all(isinstance(source, str) for source in record["sources"])
        and isinstance(record.get("conflicted"), bool)
    ):
        parsed = parse_timestamp(record.get("observed_at"))
        return {
            "value_digest": value_digest,
            "observed_at": parsed.isoformat() if parsed else None,
            "sources": sorted(set(record["sources"])),
            "conflicted": record["conflicted"],
        }
    parsed = None if node._clock_defaulted or key in {"canonical_id", "stable_id"} else parse_timestamp(node.last_seen)
    at = parsed.isoformat() if parsed else None
    return {"observed_at": at or None, "sources": sorted(set(node.data_sources)), "value_digest": value_digest, "conflicted": False}


def merge_attributes(existing: ObservedNode, incoming: ObservedNode) -> dict[str, Any]:
    """Keep one selected receipt per field; history remains in source snapshots."""
    # Replaying an unchanged observation does not manufacture new metadata.
    if (
        parse_timestamp(existing.last_seen) == parse_timestamp(incoming.last_seen)
        and existing._clock_defaulted == incoming._clock_defaulted
        and set(incoming.data_sources).issubset(existing.data_sources)
        and all(
            key in existing.attributes and existing.attributes[key] == value
            for key, value in incoming.attributes.items()
            if key != "risk_assessment"
        )
    ):
        return dict(existing.attributes)
    result: dict[str, Any] = {}
    receipts: dict[str, Any] = {}
    for key in sorted((existing.attributes.keys() | incoming.attributes.keys()) - _EXCLUDED):
        candidates = [(node.attributes[key], _receipt(node, key)) for node in (existing, incoming) if key in node.attributes]
        value, selected = max(
            candidates,
            key=lambda item: (
                item[1].get("observed_at") or "",
                1 if key in SECURITY_ASSERTIONS and item[0] is True else 0,
                item[1]["value_digest"],
            ),
        )
        selected = dict(selected)
        selected["sources"] = sorted(
            {
                source
                for _, receipt in candidates
                if receipt.get("observed_at") == selected.get("observed_at") and receipt["value_digest"] == selected["value_digest"]
                for source in receipt.get("sources", [])
            }
        )
        selected["conflicted"] = (
            any(receipt.get("conflicted") for _, receipt in candidates) or len({receipt["value_digest"] for _, receipt in candidates}) > 1
        )
        result[key] = value
        receipts[key] = selected
    if receipts:
        result[_RECEIPTS] = receipts
    return result
