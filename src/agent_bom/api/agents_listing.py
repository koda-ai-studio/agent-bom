"""Server-side paging, search, facets and sort for ``GET /v1/agents``.

The per-tenant agents response is built once and cached; every request narrows
that population here so the wire carries one bounded page plus the totals the
Agents page needs (filtered total, facet counts, population summary) instead of
every agent. Rows on the page are deep-copied so callers never mutate the cache.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import HTTPException, Query

from agent_bom.constants import is_credential_key
from agent_bom.security import sanitize_error

DEFAULT_AGENT_PAGE_SIZE = 50
MAX_AGENT_PAGE_SIZE = 500
MAX_AGENT_QUERY_LENGTH = 200
MAX_AGENT_FILTER_VALUES = 20
AGENT_SORT_KEYS = ("name", "servers", "packages", "credentials", "findings")
AgentSortKey = Literal["name", "servers", "packages", "credentials", "findings"]
SortOrder = Literal["asc", "desc"]
_FACETS = ("type", "status", "source")
_UNKNOWN = "unknown"


class AgentListQueryError(ValueError):
    """A client-supplied paging parameter is malformed; the message is safe to return."""


@dataclass(frozen=True)
class AgentListQuery:
    limit: int | None
    offset: int
    q: str
    types: frozenset[str]
    statuses: frozenset[str]
    sources: frozenset[str]
    sort: AgentSortKey | None
    order: SortOrder

    @property
    def is_legacy(self) -> bool:
        """No paging, filter or sort asked for: the pre-paging full-list contract."""
        return (
            self.limit is None
            and self.offset == 0
            and not self.q
            and not (self.types or self.statuses or self.sources)
            and self.sort is None
        )


def parse_cursor(cursor: str | None, offset: int) -> int:
    """``cursor`` is the opaque ``next_cursor`` of a previous page (a row offset)."""
    if cursor is None or cursor == "":
        return offset
    if not cursor.isdigit() or len(cursor) > 9:
        raise AgentListQueryError("cursor must be a next_cursor value returned by this endpoint")
    return int(cursor)


def _values(raw: Iterable[str] | None) -> frozenset[str]:
    values = [value.strip().lower() for value in raw or [] if value and value.strip()]
    if len(values) > MAX_AGENT_FILTER_VALUES:
        raise AgentListQueryError(f"at most {MAX_AGENT_FILTER_VALUES} values per filter")
    if any(len(value) > MAX_AGENT_QUERY_LENGTH for value in values):
        raise AgentListQueryError(f"filter values are limited to {MAX_AGENT_QUERY_LENGTH} characters")
    return frozenset(values)


def build_agent_list_query(
    *,
    limit: int | None,
    offset: int,
    cursor: str | None,
    q: str | None,
    types: list[str] | None,
    statuses: list[str] | None,
    sources: list[str] | None,
    sort: AgentSortKey | None,
    order: SortOrder | None,
) -> AgentListQuery:
    start = parse_cursor(cursor, offset)
    narrowed = q is not None and q.strip() != ""
    filtered = bool(types or statuses or sources)
    paged = start > 0 or narrowed or filtered or sort is not None
    return AgentListQuery(
        limit=limit if limit is not None else (DEFAULT_AGENT_PAGE_SIZE if paged else None),
        offset=start,
        q=(q or "").strip().lower(),
        types=_values(types),
        statuses=_values(statuses),
        sources=_values(sources),
        sort=sort,
        order=order or ("asc" if sort in (None, "name") else "desc"),
    )


def _facet_value(agent: dict[str, Any], facet: str) -> str:
    key = {"type": "agent_type", "status": "status", "source": "source"}[facet]
    value = agent.get(key)
    return str(value).strip().lower() if value not in (None, "") else _UNKNOWN


def _servers(agent: dict[str, Any]) -> list[dict[str, Any]]:
    return [server for server in agent.get("mcp_servers") or [] if isinstance(server, dict)]


def _packages(server: dict[str, Any]) -> list[dict[str, Any]]:
    return [package for package in server.get("packages") or [] if isinstance(package, dict)]


def _env_credential_keys(server: dict[str, Any]) -> list[str]:
    env = server.get("env")
    return [key for key in env if is_credential_key(str(key))] if isinstance(env, dict) else []


def server_credential_count(server: dict[str, Any]) -> int:
    """Same rule the Agents table shows: declared credential names, else credential-named env keys."""
    declared = server.get("credential_env_vars") or []
    return len(declared) if declared else len(_env_credential_keys(server))


def agent_metrics(agent: dict[str, Any]) -> dict[str, int]:
    servers = _servers(agent)
    return {
        "servers": len(servers),
        "packages": sum(len(_packages(server)) for server in servers),
        "credentials": sum(server_credential_count(server) for server in servers),
        # Package vulnerability instances, the same unit the agent mesh counts.
        "findings": sum(len(package.get("vulnerabilities") or []) for server in servers for package in _packages(server)),
    }


def _matches_search(agent: dict[str, Any], needle: str) -> bool:
    if not needle:
        return True
    haystack = (agent.get("name"), agent.get("display_name"), agent.get("agent_type"), agent.get("source"), agent.get("canonical_id"))
    return any(needle in str(value).lower() for value in haystack if value)


def _selected(query: AgentListQuery, facet: str) -> frozenset[str]:
    return {"type": query.types, "status": query.statuses, "source": query.sources}[facet]


def _passes(agent: dict[str, Any], query: AgentListQuery, *, skip: str | None = None) -> bool:
    for facet in _FACETS:
        chosen = _selected(query, facet)
        if facet != skip and chosen and _facet_value(agent, facet) not in chosen:
            return False
    return True


def _facets(searched: list[dict[str, Any]], query: AgentListQuery) -> dict[str, dict[str, int]]:
    """Each facet counts the other filters' result, so a chip never hides its siblings."""
    facets: dict[str, dict[str, int]] = {}
    for facet in _FACETS:
        counts = Counter(_facet_value(agent, facet) for agent in searched if _passes(agent, query, skip=facet))
        facets[facet] = dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    return facets


def _sort_key(sort: AgentSortKey) -> Any:
    if sort == "name":
        return lambda agent: (str(agent.get("display_name") or agent.get("name") or "").lower(), str(agent.get("canonical_id") or ""))
    return lambda agent: agent_metrics(agent)[sort]


def population_summary(agents: list[dict[str, Any]]) -> dict[str, Any]:
    """Totals for the KPI strip over every agent in scope, independent of the page."""
    servers = [server for agent in agents for server in _servers(agent)]
    mcp_servers = [server for server in servers if (server.get("surface") or "mcp-server") == "mcp-server"]
    credentials: set[str] = set()
    for server in servers:
        credentials.update(_env_credential_keys(server))
        credentials.update(str(name) for name in server.get("credential_env_vars") or [])
    ecosystems = Counter(str(package.get("ecosystem") or _UNKNOWN) for server in servers for package in _packages(server))
    configured = sum(1 for agent in agents if agent.get("status") != "installed-not-configured")
    return {
        "agents": len(agents),
        "configured": configured,
        "not_configured": len(agents) - configured,
        "mcp_servers": len(mcp_servers),
        "remote_servers": sum(1 for server in servers if any(t in str(server.get("transport") or "").lower() for t in ("sse", "http"))),
        "packages": sum(len(_packages(server)) for server in servers),
        "ecosystems": dict(sorted(ecosystems.items())),
        "unique_credentials": len(credentials),
        "servers_with_credentials": sum(1 for server in servers if server.get("credential_env_vars") or server.get("has_credentials")),
        "blocked_servers": sum(1 for server in servers if server.get("security_blocked")),
    }


def page_agents_response(response: dict[str, Any], query: AgentListQuery) -> dict[str, Any]:
    """Narrow a cached full response to the requested page without mutating it."""
    population: list[dict[str, Any]] = list(response.get("agents") or [])
    # Computed once per cached build; the cache entry is this same dict.
    summary = response.get("summary")
    if summary is None:
        summary = response["summary"] = population_summary(population)
    searched = [agent for agent in population if _matches_search(agent, query.q)]
    matched = [agent for agent in searched if _passes(agent, query)]
    if query.sort is not None:
        matched = sorted(matched, key=_sort_key(query.sort), reverse=query.order == "desc")
    total = len(matched)
    end = total if query.limit is None else query.offset + query.limit
    page = matched[query.offset : end]
    has_more = end < total
    envelope = {key: deepcopy(value) for key, value in response.items() if key != "agents"}
    envelope.update(
        {
            "agents": deepcopy(page),
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
            "has_more": has_more,
            "next_cursor": str(end) if has_more else None,
            "facets": _facets(searched, query),
            "summary": deepcopy(summary),
        }
    )
    return envelope


LEGACY_AGENT_QUERY = build_agent_list_query(
    limit=None, offset=0, cursor=None, q=None, types=None, statuses=None, sources=None, sort=None, order=None
)


def agent_list_query(
    limit: Annotated[
        int | None,
        Query(
            ge=1,
            le=MAX_AGENT_PAGE_SIZE,
            description=(
                f"Page size (1-{MAX_AGENT_PAGE_SIZE}). Defaults to {DEFAULT_AGENT_PAGE_SIZE} when any search, filter, sort or "
                "offset is given; omitted entirely, the full list is returned for older clients."
            ),
        ),
    ] = None,
    offset: Annotated[int, Query(ge=0, le=100_000_000, description="Row offset of the page")] = 0,
    cursor: Annotated[str | None, Query(max_length=16, description="Opaque next_cursor from the previous page; overrides offset")] = None,
    q: Annotated[
        str | None,
        Query(max_length=MAX_AGENT_QUERY_LENGTH, description="Case-insensitive match on name, display name, type, source or id"),
    ] = None,
    agent_type: Annotated[list[str] | None, Query(alias="type", description="Agent type; repeat for any-of")] = None,
    status: Annotated[list[str] | None, Query(description="configured or installed-not-configured; repeatable")] = None,
    source: Annotated[list[str] | None, Query(description="Discovery source; repeatable")] = None,
    sort: Annotated[AgentSortKey | None, Query(description="Sort column")] = None,
    order: Annotated[SortOrder | None, Query(description="asc or desc; name defaults to asc, counts to desc")] = None,
) -> AgentListQuery:
    """FastAPI dependency: validated ``/v1/agents`` paging, search, filter and sort parameters."""
    try:
        return build_agent_list_query(
            limit=limit,
            offset=offset,
            cursor=cursor,
            q=q,
            types=agent_type,
            statuses=status,
            sources=source,
            sort=sort,
            order=order,
        )
    except AgentListQueryError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
