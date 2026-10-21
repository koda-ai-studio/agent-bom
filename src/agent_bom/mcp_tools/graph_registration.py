"""Graph and findings MCP tools for agents: ranked paths, deploy gate, reach and findings."""

from __future__ import annotations

from typing import Annotated, Any, Callable, Literal

from pydantic import Field

from agent_bom.mcp_tools.cross_vendor_paths import cross_vendor_paths_impl
from agent_bom.mcp_tools.findings import finding_detail_impl, findings_query_impl
from agent_bom.mcp_tools.graph import deploy_decision_impl, exposure_paths_impl
from agent_bom.mcp_tools.graph_diff import graph_diff_impl
from agent_bom.mcp_tools.graph_reach import graph_reach_impl

_TENANT = Field(description="Tenant scope. Defaults to 'default'.")
_SCAN = Field(description="Optional historical scan ID. Omit for the current tenant estate.")


def _register_exposure_paths(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Exposure Paths")
    async def exposure_paths(
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum ranked exposure paths to return.")] = 5,
        view: Annotated[
            Literal["summary", "full"],
            Field(
                description=(
                    "summary (default): rank, risk, KEV, evidence tier, endpoints, finding/credential ids. "
                    "full adds hops, relationships, nodes and edges."
                )
            ),
        ] = "summary",
        min_risk: Annotated[float, Field(ge=0, le=100, description="Minimum composite path risk (0-100).")] = 0.0,
        min_severity: Annotated[
            Literal["critical", "high", "medium", "low"] | None, Field(description="Worst on-path finding at least this severe.")
        ] = None,
        kev: Annotated[bool | None, Field(description="Only paths through a known-exploited finding (true) or none (false).")] = None,
        has_credential: Annotated[
            bool | None, Field(description="Only paths that do (true) or do not (false) expose a credential.")
        ] = None,
        source_type: Annotated[str | None, Field(max_length=64, description="Entrypoint entity type, e.g. 'agent'.")] = None,
        target_id: Annotated[str | None, Field(max_length=512, description="Only paths ending at this graph node id.")] = None,
        finding_id: Annotated[str | None, Field(max_length=512, description="CVE, advisory or finding node id on the path.")] = None,
        credential_id: Annotated[str | None, Field(max_length=512, description="Credential name or node id exposed on the path.")] = None,
        node_id: Annotated[str | None, Field(max_length=512, description="Any graph node the path passes through.")] = None,
        cursor: Annotated[str | None, Field(max_length=4096, description="pagination.next_cursor; keep the filters unchanged.")] = None,
    ) -> str:
        """Return the attack-path queue in the dashboard's order, with why each path ranks where it does.

        Ranking is ``ranking.order`` (evidence tier, KEV, severity, evidence confidence,
        composite risk, credential count); every path carries ``rank``, ``evidenceTier``,
        ``isKev``, ``severity``, ``evidenceConfidence`` and ``rankingFactors``. Totals,
        filters and cursor pages match ``/v1/graph/attack-paths``.
        """
        return await execute_tool_async(
            "exposure_paths",
            exposure_paths_impl,
            tenant_id=tenant_id,
            scan_id=scan_id,
            limit=limit,
            view=view,
            min_risk=min_risk,
            min_severity=min_severity,
            kev=kev,
            has_credential=has_credential,
            source_type=source_type,
            target_id=target_id,
            finding_id=finding_id,
            credential_id=credential_id,
            node_id=node_id,
            cursor=cursor,
            _truncate_response=truncate_response,
        )


def _register_cross_vendor_paths(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Cross-Vendor Paths")
    async def cross_vendor_paths(
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
        source_vendor: Annotated[
            str | None, Field(max_length=64, description="Recorded vendor of the path's source node, e.g. 'snowflake'.")
        ] = None,
        target_vendor: Annotated[
            str | None, Field(max_length=64, description="Recorded vendor of the path's target node, e.g. 'aws'.")
        ] = None,
        offset: Annotated[int, Field(ge=0, description="Queue offset; send snapshot_generation from the first page with it.")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum paths to return.")] = 25,
        snapshot_generation: Annotated[
            str | None, Field(max_length=128, description="snapshot_generation from the first page; required when offset > 0.")
        ] = None,
    ) -> str:
        """Return attack paths whose source and target nodes are recorded in different vendors.

        Paths come in the global queue order. ``vendor_facets`` counts cross-vendor
        paths per (source vendor, target vendor) over the whole snapshot, whatever
        pair is selected; the unit is paths. Matches ``/v1/graph/attack-paths/cross-vendor``.
        """
        return await execute_tool_async(
            "cross_vendor_paths",
            cross_vendor_paths_impl,
            tenant_id=tenant_id,
            scan_id=scan_id,
            source_vendor=source_vendor,
            target_vendor=target_vendor,
            offset=offset,
            limit=limit,
            snapshot_generation=snapshot_generation,
            _truncate_response=truncate_response,
        )


def _register_should_i_deploy(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Should I Deploy")
    async def should_i_deploy(
        candidate: Annotated[
            str, Field(max_length=512, description="Package, resource, CVE, graph node ID, or deployment label to evaluate.")
        ],
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
        limit: Annotated[int, Field(ge=1, le=25, description="Maximum matched exposure paths to return.")] = 5,
        warn_risk: Annotated[
            float, Field(ge=0, le=100, description="Path risk (0-100) at or above which the decision becomes warn.")
        ] = 40.0,
        block_risk: Annotated[
            float, Field(ge=0, le=100, description="Path risk (0-100) at or above which the decision becomes block.")
        ] = 80.0,
        view: Annotated[Literal["summary", "full"], Field(description="Projection of matchedPaths.")] = "summary",
    ) -> str:
        """Return allow / warn / block / not_found for a candidate from every stored path of the snapshot.

        The candidate must exactly equal a path identifier (package name,
        name@version, purl, CVE/finding id, node id or label) in any of the
        ranked paths (``searchedPaths`` of ``total``); ``matchedPathCount``
        counts every match and ``maxRisk`` is their highest risk. A KEV finding
        reached from an agent with credential exposure blocks unless ruled
        unlikely. No exact match returns ``not_found``. Unverified reachability
        never yields allow.
        """
        return await execute_tool_async(
            "should_i_deploy",
            deploy_decision_impl,
            candidate=candidate,
            tenant_id=tenant_id,
            scan_id=scan_id,
            limit=limit,
            warn_risk=warn_risk,
            block_risk=block_risk,
            view=view,
            _truncate_response=truncate_response,
        )


def _register_graph_reach(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Graph Reach")
    async def graph_reach(
        node_id: Annotated[str, Field(max_length=512, description="Graph node ID, e.g. 'vuln:CVE-2023-4863' or 'agent:cursor'.")],
        direction: Annotated[
            Literal["in", "out"], Field(description="in: what can reach the node (as /v1/graph/impact). out: what the node reaches.")
        ] = "in",
        max_depth: Annotated[int, Field(ge=1, le=10, description="Maximum hops walked.")] = 4,
        entity_types: Annotated[
            list[str] | None, Field(max_length=32, description="Only return nodes of these entity types, e.g. ['agent'].")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="Nodes per page.")] = 50,
        cursor: Annotated[str | None, Field(max_length=4096, description="pagination.next_cursor from the previous page.")] = None,
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
    ) -> str:
        """Page the nodes connected to a node over recorded edges, with walk completeness.

        A recorded edge is not proof of execution; ``interpretation`` and
        ``completeness`` say what the bounded walk does and does not establish.
        """
        return await execute_tool_async(
            "graph_reach",
            graph_reach_impl,
            node_id=node_id,
            direction=direction,
            max_depth=max_depth,
            entity_types=entity_types,
            limit=limit,
            cursor=cursor,
            tenant_id=tenant_id,
            scan_id=scan_id,
            _truncate_response=truncate_response,
        )


def _register_graph_diff(mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]) -> None:
    @mcp.tool(annotations=read_only, title="Graph Diff")
    async def graph_diff(
        from_scan_id: Annotated[
            str | None, Field(max_length=512, description="Older snapshot scan ID. Omit both IDs to compare the latest two snapshots.")
        ] = None,
        to_scan_id: Annotated[str | None, Field(max_length=512, description="Newer snapshot scan ID.")] = None,
        view: Annotated[
            Literal["summary", "detail", "estate"],
            Field(
                description=(
                    "summary (default): counts per change kind by entity type and relationship, plus new critical findings, "
                    "new credential reach, removed controls and new attack paths. detail: a filtered page of change rows. "
                    "estate: each current source against its own previous snapshot, as /v1/graph/changes; "
                    "first observations are listed separately, never counted as additions."
                )
            ),
        ] = "summary",
        change: Annotated[Literal["added", "removed", "changed"] | None, Field(description="detail: only this change kind.")] = None,
        kind: Annotated[Literal["node", "edge"] | None, Field(description="detail: only node or edge rows.")] = None,
        entity_type: Annotated[str | None, Field(max_length=64, description="detail: only node rows of this entity type.")] = None,
        relationship: Annotated[str | None, Field(max_length=64, description="detail: only edge rows of this relationship.")] = None,
        node_id: Annotated[str | None, Field(max_length=512, description="detail: the node itself or edges touching it.")] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="detail: rows per page; estate: sources per page (max 100).")] = 50,
        cursor: Annotated[str | None, Field(max_length=4096, description="pagination.next_cursor; keep the filters unchanged.")] = None,
        offset: Annotated[int, Field(ge=0, description="estate: pagination.next_offset from the previous page.")] = 0,
        tenant_id: Annotated[str, _TENANT] = "default",
    ) -> str:
        """Return what changed between two graph snapshots exactly as /v1/graph/diff does, or per source with view=estate.

        Rows are ordered nodes before edges, then added/removed/changed, then id;
        ``total`` counts every row matching the filters, not one page.
        """
        return await execute_tool_async(
            "graph_diff",
            graph_diff_impl,
            tenant_id=tenant_id,
            from_scan_id=from_scan_id,
            to_scan_id=to_scan_id,
            view=view,
            change=change,
            kind=kind,
            entity_type=entity_type,
            relationship=relationship,
            node_id=node_id,
            limit=limit,
            cursor=cursor,
            offset=offset,
            _truncate_response=truncate_response,
        )


def _register_findings_query(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Findings Query")
    async def findings_query(
        lane: Annotated[
            str | None, Field(max_length=32, description="Finding lane: vulnerabilities, cloud, iac, secrets, identity, data, other.")
        ] = None,
        q: Annotated[str | None, Field(max_length=256, description="Free-text match on title, advisory or package.")] = None,
        severity: Annotated[str | None, Field(max_length=16, description="Exact severity: critical, high, medium, low.")] = None,
        kev: Annotated[bool | None, Field(description="Only known-exploited findings (true) or only non-KEV (false).")] = None,
        framework: Annotated[str | None, Field(max_length=64, description="Compliance framework drill-through, e.g. 'owasp-llm'.")] = None,
        control: Annotated[str | None, Field(max_length=64, description="Control code within framework, e.g. 'LLM05'.")] = None,
        reachability: Annotated[
            Literal["reachable", "unreachable", "unassessed"] | None, Field(description="Graph reachability filter.")
        ] = None,
        triage: Annotated[
            Literal["not_affected", "affected", "under_investigation", "untriaged"] | None, Field(description="Triage/VEX state filter.")
        ] = None,
        sort: Annotated[str, Field(max_length=32, description="Sort key, as /v1/findings (default effective_reach).")] = "effective_reach",
        limit: Annotated[int, Field(ge=1, le=200, description="Findings per page.")] = 25,
        cursor: Annotated[str | None, Field(max_length=512, description="next_cursor from the previous page.")] = None,
        fields: Annotated[Literal["summary", "full"], Field(description="summary (default) or the full /v1/findings row.")] = "summary",
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
    ) -> str:
        """Query the tenant's findings exactly as /v1/findings does, with a compact row projection.

        ``risk_score`` is 0-10 (advisory severity); ``effective_reach_score`` is
        0-100 (exposure-weighted). Use ``finding_detail`` for one finding's paths.
        """
        return await execute_tool_async(
            "findings_query",
            findings_query_impl,
            lane=lane,
            q=q,
            severity=severity,
            kev=kev,
            framework=framework,
            control=control,
            reachability=reachability,
            triage=triage,
            sort=sort,
            limit=limit,
            cursor=cursor,
            fields=fields,
            tenant_id=tenant_id,
            scan_id=scan_id,
            _truncate_response=truncate_response,
        )


def _register_finding_detail(
    mcp: Any, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    @mcp.tool(annotations=read_only, title="Finding Detail")
    async def finding_detail(
        finding_id: Annotated[str, Field(max_length=256, description="Finding id from findings_query or blast_radius.")],
        path_limit: Annotated[int, Field(ge=1, le=25, description="Maximum graph paths to return for the finding.")] = 5,
        tenant_id: Annotated[str, _TENANT] = "default",
        scan_id: Annotated[str | None, _SCAN] = None,
    ) -> str:
        """Return one finding with its graph paths, who reaches it, its exploit story and its triage/VEX state."""
        return await execute_tool_async(
            "finding_detail",
            finding_detail_impl,
            finding_id=finding_id,
            path_limit=path_limit,
            tenant_id=tenant_id,
            scan_id=scan_id,
            _truncate_response=truncate_response,
        )


def register_graph_agent_tools(
    mcp: Any, *, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    """Register the graph tools whose answers match the dashboard queue and REST reads."""
    for register in (
        _register_exposure_paths,
        _register_cross_vendor_paths,
        _register_should_i_deploy,
        _register_graph_reach,
        _register_graph_diff,
        _register_findings_query,
        _register_finding_detail,
    ):
        register(mcp, read_only, execute_tool_async, truncate_response)


__all__ = ["register_graph_agent_tools"]
