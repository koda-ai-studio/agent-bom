"""Bounded, replay-safe unions of metadata-only recorded activity receipts."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

SOURCE = "persisted-runtime-activity"
MAX_EVENTS = 20_000


def merge_activity_receipts(stored: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Retain complete source receipts when snapshots or repeated builds merge."""
    if stored.get("source") != SOURCE or incoming.get("source") != SOURCE:
        return False
    rows = {
        json.dumps(row, sort_keys=True): row
        for evidence in (stored, incoming)
        for row in evidence.get("receipts", [])[:MAX_EVENTS]
        if isinstance(row, dict)
    }
    receipts = [deepcopy(rows[key]) for key in sorted(rows)[:MAX_EVENTS]]
    limited = any(evidence.get("receipts_truncated") for evidence in (stored, incoming)) or len(rows) > MAX_EVENTS
    changed = stored.get("receipts") != receipts or stored.get("event_count") != len(receipts)
    if limited and stored.get("receipts_truncated") is not True:
        stored["receipts_truncated"] = True
        changed = True
    stored.update(receipts=receipts, event_count=len(receipts))
    return changed
