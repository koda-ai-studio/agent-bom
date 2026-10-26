"""Graphs MCP registrations with per-server dispatch bindings."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from typing import Annotated, Any

from pydantic import Field

from agent_bom.mcp_errors import CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tools.graph_export_persisted import (
    EXPORT_PAGE_DEFAULT,
    EXPORT_PAGE_MAX,
    persisted_export_graph,
    persisted_export_mode,
)

from .bindings import OperatorToolBindings


def register_context_graph(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Context Graph")
    async def context_graph(
        config_path: Annotated[
            str | None,
            Field(description="MCP config directory to scan live on this host. Implies live=true."),
        ] = None,
        source_agent: Annotated[
            str | None,
            Field(description="Agent name to compute lateral paths from. Omit for all agents."),
        ] = None,
        max_depth: Annotated[
            int,
            Field(description="Max BFS depth for lateral path discovery (1-6, default 4)."),
        ] = 4,
        tenant_id: Annotated[str, Field(description="Tenant scope for the persisted snapshot. Defaults to 'default'.")] = "default",
        scan_id: Annotated[str | None, Field(description="Persisted scan to read. Omit for the tenant's current snapshot.")] = None,
        live: Annotated[
            bool,
            Field(description="Discover this MCP server host's agent configurations instead of reading the persisted snapshot."),
        ] = False,
        offset: Annotated[int, Field(ge=0, description="Agent page offset into the current estate graph.")] = 0,
        limit: Annotated[int, Field(ge=1, le=100, description="Agents per page (1-100, default 25).")] = 25,
    ) -> str:
        """Build an agent context graph with lateral movement analysis.

        Models reachability between agents, servers, credentials, tools,
        and vulnerabilities.  Answers: "If agent X is compromised, what
        else becomes reachable?"

        Reads one agent page of the tenant's current estate graph by default
        (the agents ``GET /v1/graph?entity_types=agent`` pages, with their
        servers, packages, tools, credential names and advisories); ``scan_id``
        reads that persisted scan instead. Live host discovery runs only with
        ``live=true`` or a ``config_path``; a tenant without a snapshot gets an
        error, never a silent scan of this host.

        Returns:
            JSON with nodes, edges, lateral_paths, interaction_risks, stats,
            completeness, pagination, estate_coverage, source
            (current_estate_graph | persisted_snapshot | live_discovery) and scope.
        """
        return await bindings.execute_tool_async(
            "context_graph",
            bindings.implementations["context_graph_impl"],
            config_path=config_path,
            source_agent=source_agent,
            max_depth=max_depth,
            tenant_id=tenant_id,
            scan_id=scan_id,
            live=live,
            offset=offset,
            limit=limit,
            _run_scan_pipeline=bindings.run_scan_pipeline,
            _truncate_response=bindings.truncate_response,
        )


def _render_export(bindings: OperatorToolBindings, graph: Any, metadata: dict[str, Any], fmt: str, mermaid_limit: int) -> str:
    renderers = {
        "graphml": lambda: bindings.implementations["_to_graphml"](graph),
        "cypher": lambda: bindings.implementations["_to_cypher"](graph),
        "dot": lambda: bindings.implementations["_to_dot"](graph),
        "mermaid": lambda: (
            bindings.implementations["_to_mermaid"](graph, max_nodes=None, max_edges=None)
            if mermaid_limit == 0
            else bindings.implementations["_to_mermaid"](graph, max_nodes=mermaid_limit)
        ),
    }
    if fmt in renderers:
        return str(renderers[fmt]())
    document = {**bindings.implementations["_graph_to_json"](graph), **metadata}
    # Persisted pages are sized against the response budget, so they are rendered compactly.
    return json.dumps(document, separators=(",", ":")) if metadata else json.dumps(document, indent=2)


async def _persisted_export(
    bindings: OperatorToolBindings, render: Callable[[Any, dict[str, Any]], str], limit: int, cursor: str | None
) -> str:
    """One persisted page; a page the transport would trim is re-read smaller, so completeness and the cursor stay true."""
    page_size = limit
    while True:
        exported = await persisted_export_graph(limit=page_size, cursor=cursor)
        if isinstance(exported, str):
            return str(bindings.truncate_response(exported))
        rendered = render(*exported)
        bounded = str(bindings.truncate_response(rendered))
        if bounded == rendered or page_size == 1:
            return bounded
        page_size = max(1, min(page_size - 1, int(page_size * len(bounded) / len(rendered) * 0.9)))


def register_graph_export(bindings: OperatorToolBindings) -> None:
    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Graph Export")
    async def graph_export(
        config_path: Annotated[
            str | None,
            Field(description="Path to MCP config directory. Omit to auto-discover."),
        ] = None,
        format: Annotated[
            str,
            Field(description="Export format: graphml, cypher, dot, mermaid, or json (default)."),
        ] = "json",
        mermaid_limit: Annotated[
            int,
            Field(
                ge=0,
                le=5000,
                description="Maximum nodes rendered for Mermaid output; 0 renders the full graph.",
            ),
        ] = 80,
        limit: Annotated[
            int,
            Field(
                ge=1,
                le=EXPORT_PAGE_MAX,
                description="Persisted export: nodes per page (default 1000); a page too large for the response shrinks.",
            ),
        ] = EXPORT_PAGE_DEFAULT,
        cursor: Annotated[
            str | None,
            Field(description="Persisted export: pagination.next_cursor from the previous JSON page; pinned to that snapshot generation."),
        ] = None,
    ) -> str:
        """Export the agent dependency graph in graph-native formats.

        A tenant-bound (or Postgres-backed) server exports the tenant's
        persisted current-estate graph one page at a time (``limit``/``cursor``),
        labelled with ``source``/``scope``/``completeness``/``pagination`` in
        JSON; each page owns its nodes and their outgoing edges, and an edge's
        target on another page appears as a ``page_reference`` stub. It never
        scans this host; ``config_path`` exports that directory's agents instead.

        Formats:
        - **graphml** — yEd, Gephi, NetworkX compatible with AIBOM-typed attributes
        - **cypher** — Neo4j import script with AIBOM node labels (AIAgent, MCPServer, Package, Vulnerability)
        - **dot** — Graphviz (pipe through ``dot -Tsvg``)
        - **mermaid** — embed in markdown, GitHub, Notion
        - **json** — machine-readable nodes/edges list

        Returns:
            Graph in the requested format as a string.
        """

        async def _host_graph() -> tuple[Any, dict[str, Any]] | str:
            scan_result = await bindings.run_scan_pipeline(config_path=config_path)
            if isinstance(scan_result, str):
                return scan_result
            agents, _blast_radii, _warnings, _sources = scan_result
            return bindings.build_dep_graph_from_agents([asdict(agent) for agent in agents]), {}

        async def _impl() -> str:
            def render(graph: Any, metadata: dict[str, Any]) -> str:
                return _render_export(bindings, graph, metadata, format.lower(), mermaid_limit)

            if config_path is None and persisted_export_mode():
                return await _persisted_export(bindings, render, limit, cursor)
            if cursor:
                return mcp_error_json(
                    CODE_VALIDATION_INVALID_ARGUMENT, "cursor applies only to persisted exports", details={"argument": "cursor"}
                )
            exported = await _host_graph()
            if isinstance(exported, str):
                return bindings.truncate_response(exported)
            return bindings.truncate_response(render(*exported))

        return await bindings.execute_tool_async("graph_export", _impl)


def register_analytics_query(bindings: OperatorToolBindings) -> None:

    mcp = bindings.mcp

    @mcp.tool(annotations=bindings.read_only, title="Analytics Query")
    async def analytics_query(
        query_type: Annotated[
            str,
            Field(description=("Query type: vuln_trends, top_cves, posture_history, event_summary, fleet_riskiest, or compliance_heatmap")),
        ],
        days: Annotated[
            int,
            Field(description="Lookback window in days (default 30). Used by vuln_trends, posture_history, and compliance_heatmap."),
        ] = 30,
        hours: Annotated[
            int,
            Field(description="Lookback window in hours (default 24). Used by event_summary."),
        ] = 24,
        agent: Annotated[
            str | None,
            Field(description="Filter by agent name. Used by vuln_trends and posture_history."),
        ] = None,
        limit: Annotated[
            int,
            Field(description="Max results for top_cves and fleet_riskiest (default 20)."),
        ] = 20,
    ) -> str:
        """Query vulnerability trends, posture history, and runtime event summaries from ClickHouse.

        Requires AGENT_BOM_CLICKHOUSE_URL to be set. Returns empty results if
        ClickHouse is not configured.
        """
        return await bindings.execute_tool_async(
            "analytics_query",
            bindings.implementations["analytics_query_impl"],
            query_type=query_type,
            days=days,
            hours=hours,
            agent=agent,
            limit=limit,
            _truncate_response=bindings.truncate_response,
        )


REGISTRATIONS = (
    register_context_graph,
    register_graph_export,
    register_analytics_query,
)
