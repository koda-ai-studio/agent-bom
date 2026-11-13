"""Response contract for the paged agents list (``GET /v1/agents``)."""

from __future__ import annotations

from agent_bom.api.read_models._base import ReadModel, ReadResponse
from agent_bom.api.read_models.posture import DiscoveredAgent


class AgentsSummary(ReadModel):
    """Population totals over every agent in scope, independent of the page and filters."""

    agents: int
    configured: int
    not_configured: int
    mcp_servers: int
    remote_servers: int
    packages: int
    ecosystems: dict[str, int]
    unique_credentials: int
    servers_with_credentials: int
    blocked_servers: int


class AppliedSort(ReadModel):
    key: str
    order: str


class AgentsResponse(ReadResponse):
    # This page of agents; ``count`` and ``summary`` cover every agent in scope.
    agents: list[DiscoveredAgent]
    count: int
    # Rows matching the search and filters; ``agents`` is the page at ``offset``.
    total: int
    limit: int | None
    offset: int
    has_more: bool
    next_cursor: str | None
    # The sort the server applied to these rows; null is first-seen order.
    sort: AppliedSort | None
    # Per-filter value counts; each facet ignores its own selection.
    facets: dict[str, dict[str, int]]
    summary: AgentsSummary
    count_by_class: dict[str, int]
    scope: str
    source: str
    warnings: list[str]
    count_definition: str | None = None
