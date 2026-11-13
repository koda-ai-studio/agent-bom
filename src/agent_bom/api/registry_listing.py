"""Server-side paging, search and facets for ``GET /v1/registry`` (the MCP catalog)."""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

MAX_REGISTRY_PAGE_SIZE = 500
MAX_REGISTRY_QUERY_LENGTH = 200
RegistryRisk = Literal["high", "medium", "low", "unknown"]
_SEARCH_FIELDS = ("id", "name", "description", "publisher", "category")


def _risk(server: dict[str, Any]) -> str:
    return str(server.get("risk_level") or "unknown").lower()


def _matches(server: dict[str, Any], needle: str) -> bool:
    return not needle or any(needle in str(server.get(field) or "").lower() for field in _SEARCH_FIELDS)


def _counts(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items(), key=lambda item: (-item[1], item[0])))


def page_registry(
    servers: list[dict[str, Any]],
    *,
    limit: int | None,
    offset: int,
    q: str | None,
    risk: list[str] | None,
    category: list[str] | None,
) -> dict[str, Any]:
    """One page of the catalog plus the matching total and per-filter counts.

    Rows are returned as-is: the catalog is an immutable bundled list, and the
    response serializer copies them onto the wire.
    """
    needle = (q or "").strip().lower()
    risks = {value.lower() for value in risk or []}
    categories = set(category or [])
    searched = [server for server in servers if _matches(server, needle)]

    def in_risk(server: dict[str, Any]) -> bool:
        return not risks or _risk(server) in risks

    def in_category(server: dict[str, Any]) -> bool:
        return not categories or server.get("category") in categories

    matched = [server for server in searched if in_risk(server) and in_category(server)]
    total = len(matched)
    end = total if limit is None else offset + limit
    has_more = end < total
    return {
        "servers": matched[offset:end],
        "count": len(servers),
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
        "next_cursor": str(end) if has_more else None,
        "facets": {
            "risk_level": _counts([_risk(s) for s in searched if in_category(s)]),
            "category": _counts([str(s["category"]) for s in searched if in_risk(s) and s.get("category")]),
        },
        "risk_counts": _counts([_risk(s) for s in servers]),
    }
