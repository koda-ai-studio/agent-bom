"""``/v1/graph`` node-page continuation: the keyset cursor carries its snapshot generation."""

from __future__ import annotations

import base64
import binascii
import json

from fastapi import HTTPException

from agent_bom.api.current_graph import refuse_unpinned_read_while_seeding

_NODE_CURSOR_PREFIX = "g1."


def wrap_node_cursor(store_cursor: str | None, generation: str) -> str | None:
    """A node-page cursor that carries the generation it continues."""
    if not store_cursor or not generation:
        return store_cursor
    payload = json.dumps([generation, store_cursor], separators=(",", ":")).encode()
    return _NODE_CURSOR_PREFIX + base64.urlsafe_b64encode(payload).decode().rstrip("=")


def continue_node_cursor(cursor: str | None, generation: str | None) -> tuple[str | None, str | None]:
    """``(store cursor, generation to pin)``; a supplied generation must match the cursor's (409)."""
    if not cursor or not cursor.startswith(_NODE_CURSOR_PREFIX):
        return cursor, generation
    encoded = cursor[len(_NODE_CURSOR_PREFIX) :]
    try:
        carried, store_cursor = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(422, "Invalid cursor for this query; restart from the first page.") from exc
    if not isinstance(carried, str) or not isinstance(store_cursor, str):
        raise HTTPException(422, "Invalid cursor for this query; restart from the first page.")
    if generation is not None and generation != carried:
        raise HTTPException(409, "snapshot_generation does not match the cursor's; restart the query from its first page.")
    return store_cursor, carried


def node_page_continuation(requested_scan_id: str, cursor: str | None, generation: str | None) -> tuple[str | None, str | None]:
    """Admission for a ``/v1/graph`` node page: ``(store cursor, generation to pin)``."""
    refuse_unpinned_read_while_seeding(requested_scan_id)
    return continue_node_cursor(cursor, generation)
