"""Intel MCP tool registration."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field


def _register_intel_lookup(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Threat Intel Advisory Lookup")
    async def intel_lookup(
        advisory_id: Annotated[str, Field(description="CVE, GHSA, or OSV advisory ID, e.g. CVE-2024-1234 or GHSA-abcd-1234-wxyz.")],
    ) -> str:
        """Look up one advisory from the local threat-intel database."""

        return await _execute_tool_async(
            "intel_lookup",
            impl,
            advisory_id=advisory_id,
            _truncate_response=_truncate_response,
        )


def _register_intel_match(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Threat Intel Package Match")
    async def intel_match(
        purl: Annotated[str | None, Field(description="Package URL, e.g. pkg:pypi/requests@2.31.0.")] = None,
        ecosystem: Annotated[
            str | None,
            Field(description="Package ecosystem when purl is omitted, e.g. pypi, npm, go, maven, apk."),
        ] = None,
        name: Annotated[str | None, Field(description="Package name when purl is omitted.")] = None,
        version: Annotated[str | None, Field(description="Package version when known.")] = None,
        packages: Annotated[
            list[dict] | None,
            Field(description="Optional package list with purl or ecosystem/name/version objects for batch matching."),
        ] = None,
        limit: Annotated[int, Field(description="Maximum packages to match, 1-500.")] = 100,
    ) -> str:
        """Match package inventory coordinates to local threat-intel advisories."""

        return await _execute_tool_async(
            "intel_match",
            impl,
            packages=packages,
            purl=purl,
            ecosystem=ecosystem,
            name=name,
            version=version,
            limit=limit,
            _truncate_response=_truncate_response,
        )


def _register_intel_sources(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Threat Intel Source Catalog")
    async def intel_sources() -> str:
        """Return canonical threat-intel sources and local feed-run freshness."""

        return await _execute_tool_async(
            "intel_sources",
            impl,
            _truncate_response=_truncate_response,
        )


def _register_intel_daily_brief(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Threat Intel Daily Brief")
    async def intel_daily_brief(
        packages: Annotated[
            list[dict] | None,
            Field(description="Optional inventory packages with purl or ecosystem/name/version objects for local matching."),
        ] = None,
        telemetry_indicators: Annotated[
            list[dict] | None,
            Field(
                description=(
                    "Optional governed IoC observations with indicator, hit_count, source_url, license, fetched_at, and content_hash."
                )
            ),
        ] = None,
        campaign_activity: Annotated[
            list[dict] | None,
            Field(description="Optional governed campaign activity items with sectors/geos and provenance for tenant-profile matching."),
        ] = None,
        ransomware_claims: Annotated[
            list[dict] | None,
            Field(description="Optional governed ransomware claim items with sectors/geos and provenance for tenant-profile matching."),
        ] = None,
        tenant_profile: Annotated[
            dict | None,
            Field(description="Optional tenant profile with sectors and geos used to match campaign/ransomware inputs."),
        ] = None,
        epss_threshold: Annotated[float, Field(description="Minimum EPSS probability for inventory-prioritized CVEs, 0-1.")] = 0.7,
        kev_window_hours: Annotated[int, Field(description="KEV date_added lookback window, 1-168 hours.")] = 24,
        limit: Annotated[int, Field(description="Maximum packages/advisories to inspect, 1-500.")] = 100,
    ) -> str:
        """Return a local analyst threat brief from governed intel sources."""

        return await _execute_tool_async(
            "intel_daily_brief",
            impl,
            packages=packages,
            telemetry_indicators=telemetry_indicators,
            campaign_activity=campaign_activity,
            ransomware_claims=ransomware_claims,
            tenant_profile=tenant_profile,
            epss_threshold=epss_threshold,
            kev_window_hours=kev_window_hours,
            limit=limit,
            _truncate_response=_truncate_response,
        )


def _register_youcom_search(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Threat Intel You.com Search")
    async def youcom_search(
        query: Annotated[
            str,
            Field(
                description=("Free-text query for You.com web/news search, e.g. 'CVE-2026-12345 exploit' or 'latest MCP security news'.")
            ),
        ],
        count: Annotated[int, Field(description="Results per section, 1-100.")] = 10,
        freshness: Annotated[
            str | None,
            Field(description="Optional freshness filter: day, week, month, year, or YYYY-MM-DDtoYYYY-MM-DD."),
        ] = None,
        country: Annotated[str | None, Field(description="Optional two-letter country code, e.g. US.")] = None,
        language: Annotated[str | None, Field(description="Optional BCP 47 language code, e.g. en.")] = None,
        safesearch: Annotated[str | None, Field(description="Optional safesearch level: off, moderate, strict.")] = None,
        livecrawl: Annotated[str | None, Field(description="Optional livecrawl mode: web, news, or all.")] = None,
        crawl_timeout: Annotated[int, Field(description="Optional livecrawl timeout in seconds, 1-60.")] = 10,
    ) -> str:
        """Search You.com for current web or news context."""

        return await _execute_tool_async(
            "youcom_search",
            impl,
            query=query,
            count=count,
            freshness=freshness,
            country=country,
            language=language,
            safesearch=safesearch,
            livecrawl=livecrawl,
            crawl_timeout=crawl_timeout,
            _truncate_response=_truncate_response,
        )


def _register_affected_assets(mcp: Any, *, impl: Any, read_only: Any, _execute_tool_async: Any, _truncate_response: Any) -> None:

    @mcp.tool(annotations=read_only, title="Assets Affected By An Advisory")
    async def affected_assets(
        advisory_id: Annotated[str, Field(description="CVE, GHSA or operator advisory id (or alias), e.g. CVE-2026-109618.")],
        verdict: Annotated[str, Field(description="all, affected, possibly_affected or not_affected.")] = "all",
        limit: Annotated[int, Field(description="Rows per page, 1-200.")] = 50,
        cursor: Annotated[str | None, Field(description="next_cursor from the previous page.")] = None,
    ) -> str:
        """Which scanned assets an advisory affects: affected, possibly affected (distro) and not affected, with patch targets."""

        return await _execute_tool_async(
            "affected_assets",
            impl,
            advisory_id=advisory_id,
            verdict=verdict,
            limit=limit,
            cursor=cursor,
            _truncate_response=_truncate_response,
        )


def register_intel_tools(mcp: Any, **context: Any) -> None:
    """Register intel tools with shared execution callbacks."""
    from agent_bom.mcp_tools.affected_assets import affected_assets_impl
    from agent_bom.mcp_tools.intel import (
        intel_daily_brief_impl,
        intel_lookup_impl,
        intel_match_impl,
        intel_sources_impl,
        youcom_search_impl,
    )

    _register_intel_lookup(mcp, impl=intel_lookup_impl, **context)
    _register_intel_match(mcp, impl=intel_match_impl, **context)
    _register_intel_sources(mcp, impl=intel_sources_impl, **context)
    _register_intel_daily_brief(mcp, impl=intel_daily_brief_impl, **context)
    _register_youcom_search(mcp, impl=youcom_search_impl, **context)
    _register_affected_assets(mcp, impl=affected_assets_impl, **context)
