"""Opaque cursor encoding for the compliance-hub finding list."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any


def _unpack_hub_list_page(result: tuple[Any, ...]) -> tuple[list[dict[str, Any]], int | None, str | None]:
    page = result[0]
    total = result[1] if len(result) > 1 else None
    next_cursor = result[2] if len(result) > 2 else None
    return page, total, next_cursor


_HUB_LIST_CURSOR_VERSION = 1


def _hub_native_fingerprint(findings: list[dict[str, Any]]) -> str:
    ids = [str(row.get("id") or "") for row in findings]
    raw = json.dumps(ids, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()[:24]


def _hub_tenant_fingerprint(tenant_id: str) -> str:
    return hashlib.sha256(tenant_id.encode()).hexdigest()[:24]


def _encode_hub_list_cursor(
    *,
    tenant_id: str,
    native_findings: list[dict[str, Any]],
    native_index: int,
    hub_cursor: str,
    total: int,
) -> str:
    payload = {
        "v": _HUB_LIST_CURSOR_VERSION,
        "t": _hub_tenant_fingerprint(tenant_id),
        "n": native_index,
        "nf": _hub_native_fingerprint(native_findings),
        "h": hub_cursor,
        "total": total,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_hub_list_cursor(
    cursor: str,
    *,
    tenant_id: str,
    native_findings: list[dict[str, Any]],
) -> tuple[int, str, int]:
    try:
        if not cursor or len(cursor) > 4096:
            raise ValueError
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.b64decode(padded.encode(), altchars=b"-_", validate=True).decode())
        if not isinstance(payload, dict) or payload.get("v") != _HUB_LIST_CURSOR_VERSION:
            raise ValueError
        if payload.get("t") != _hub_tenant_fingerprint(tenant_id):
            raise ValueError
        if payload.get("nf") != _hub_native_fingerprint(native_findings):
            raise ValueError
        native_index = int(payload["n"])
        total = int(payload["total"])
        hub_cursor = str(payload.get("h") or "")
        if native_index < 0 or native_index > len(native_findings) or total < 0:
            raise ValueError
        return native_index, hub_cursor, total
    except Exception as exc:
        raise ValueError("Invalid or stale compliance hub cursor") from exc


def _cursor_walk_page(
    list_page: Callable[..., tuple[Any, ...]],
    *,
    tenant_id: str,
    native: list[dict[str, Any]],
    native_index: int,
    hub_cursor: str,
    stable_total: int,
    safe_limit: int,
    sort: str,
    cursor: str | None,
) -> tuple[list[dict[str, Any]], int, str]:
    """Walk the native prefix then the durable hub keyset for one cursor page."""
    page = native[native_index : native_index + safe_limit]
    next_native_index = native_index + len(page)
    remaining = safe_limit - len(page)
    hub_rows: list[dict[str, Any]] = []
    hub_total: int | None = None
    hub_next: str | None = None
    if remaining > 0:
        hub_rows, hub_total, hub_next = _unpack_hub_list_page(
            list_page(
                tenant_id,
                limit=remaining,
                offset=0,
                sort=sort,
                include_total=not cursor,
                cursor=hub_cursor or None,
            )
        )
        page.extend(hub_rows)
    elif not cursor:
        # Exact first-page total without hydrating a durable row. A limit=0
        # query fetches only the keyset lookahead and returns COUNT(*).
        _unused, hub_total, _unused_cursor = _unpack_hub_list_page(list_page(tenant_id, limit=0, offset=0, sort=sort, include_total=True))

    total = stable_total if cursor else len(native) + int(hub_total or 0)
    has_native_more = next_native_index < len(native)
    hub_unstarted_with_rows = remaining == 0 and not hub_cursor and total > len(native)
    has_hub_more = bool(hub_next) or hub_unstarted_with_rows
    if has_native_more or has_hub_more:
        continuation_hub_cursor = hub_cursor if remaining == 0 else str(hub_next or "")
        next_cursor = _encode_hub_list_cursor(
            tenant_id=tenant_id,
            native_findings=native,
            native_index=next_native_index,
            hub_cursor=continuation_hub_cursor,
            total=total,
        )
    else:
        next_cursor = ""
    return page, total, next_cursor
