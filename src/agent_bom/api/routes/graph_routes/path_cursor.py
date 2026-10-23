"""Opaque continuation cursors for the path queues, pinned to tenant, query and generation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import HTTPException

from agent_bom.graph.diff_view import decode_cursor, encode_cursor


def path_cursor_scope(kind: str, tenant: str, scan_id: str | None, filters: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([kind, tenant, scan_id or "", sorted(filters.items())]).encode()).hexdigest()


def path_continuation(cursor: str, scope: str, *, offset: int, generation: str | None) -> tuple[int, str]:
    """Offset and pinned generation a ``next_cursor`` carries for this tenant and query."""
    if offset or generation:
        raise HTTPException(400, "cursor replaces offset and snapshot_generation; send only the cursor.")
    try:
        continuation = decode_cursor(cursor, scope)
    except ValueError as exc:
        raise HTTPException(400, "Invalid cursor for this query; restart from the first page.") from exc
    return continuation["offset"], continuation["revision"]


def path_page_cursors(scope: str, generation: str, offset: int, returned: int, total: int, cursor: str | None) -> dict[str, Any]:
    """``has_more`` is true only with a ``next_cursor`` that continues the page."""
    next_offset = offset + returned
    has_more = bool(returned) and next_offset < total
    return {"cursor": cursor or "", "next_cursor": encode_cursor(scope, generation, next_offset) if has_more else "", "has_more": has_more}
