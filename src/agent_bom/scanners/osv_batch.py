"""Parse OSV ``/v1/querybatch`` payloads and follow paginated results."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from agent_bom.core.errors import UpstreamError, UpstreamInvalidResponseError
from agent_bom.enrichment_posture import record_enrichment_source
from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name

_logger = logging.getLogger("agent_bom.scanners.osv")

PageFetch = Callable[[list[int], list[dict]], Awaitable["dict[int, str] | None"]]


@dataclass(frozen=True)
class UnfinishedQueries:
    """Query indexes whose results were not fully read, and whether the page limit stopped them."""

    indexes: frozenset[int]
    limit_reached: bool


async def follow_result_pages(
    tokens: dict[int, str],
    queries: list[dict],
    fetch: PageFetch,
    bump_scan_perf: Callable[[str, int], None],
    max_pages: int,
) -> UnfinishedQueries:
    """Ask for the next page of every paginated query until none is left.

    OSV paginates a query past about 1,000 advisories (or a batch past about
    3,000); each further page is requested with that query's ``page_token``.
    ``fetch`` merges a page and returns its tokens, or None after recording a
    failure for the queries it was asked about.
    """
    pages = 0
    while tokens and pages < max_pages:
        pages += 1
        bump_scan_perf("osv_page_followups", 1)
        indexes = sorted(tokens)
        next_tokens = await fetch(indexes, [dict(queries[idx], page_token=tokens[idx]) for idx in indexes])
        if next_tokens is None:
            return UnfinishedQueries(frozenset(indexes), limit_reached=False)
        tokens = next_tokens
    return UnfinishedQueries(frozenset(tokens), limit_reached=bool(tokens))


def collect_batch_vulns(
    data: Any,
    query_indexes: list[int],
    pkg_index: dict[int, tuple[Package, str]],
    partial: dict[str, list[dict]],
    console: Console,
) -> dict[int, str]:
    """Merge one ``/v1/querybatch`` payload into ``partial``; raise on a malformed shape.

    Returns ``{query index: next_page_token}`` for each query OSV paginated;
    the caller fetches those pages before treating the query as complete.
    """
    if not isinstance(data, dict):
        raise ValueError(f"unexpected payload type: {type(data).__name__}")
    osv_results = data.get("results")
    if not isinstance(osv_results, list):
        raise ValueError("OSV results must be an array")
    batch_len = len(query_indexes)
    page_tokens: dict[int, str] = {}
    if len(osv_results) != batch_len:
        _logger.warning(
            "OSV batch response length mismatch: sent %d queries, got %d results. Some packages may have missed vulnerability detection.",
            batch_len,
            len(osv_results),
        )
        console.print(
            f"  [yellow]⚠[/yellow] OSV batch response length mismatch:"
            f" sent {batch_len} queries, got {len(osv_results)} results."
            f" [dim]Some packages may have missed vulnerability detection.[/dim]"
        )
    incomplete = len(osv_results) != batch_len
    for index, result in enumerate(osv_results[:batch_len]):
        if not isinstance(result, dict):
            raise ValueError("OSV result must be an object")
        if result.get("error"):
            incomplete = True
        token = result.get("next_page_token")
        if token:
            if not isinstance(token, str):
                raise ValueError("OSV next_page_token must be a string")
            page_tokens[query_indexes[index]] = token
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list) or any(
            not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"].strip() for vuln in vulns
        ):
            raise ValueError("OSV vulnerabilities must contain advisory identifiers")
        pkg_match = pkg_index.get(query_indexes[index])
        if not vulns or not pkg_match:
            continue
        pkg_obj = pkg_match[0]
        key = f"{pkg_obj.ecosystem.lower()}:{normalize_package_name(pkg_obj.name, pkg_obj.ecosystem)}@{pkg_obj.version}"
        existing = partial.setdefault(key, [])
        seen_ids = {item.get("id") for item in existing}
        for vuln in vulns:
            if vuln.get("id") not in seen_ids:
                existing.append(vuln)
                seen_ids.add(vuln.get("id"))
    if incomplete:
        # Retain observed findings, but never cache this incomplete batch.
        raise ValueError("OSV batch response is incomplete")
    return page_tokens


def merge_batch_response(
    read_json: Callable[[], Any],
    query_indexes: list[int],
    pkg_index: dict[int, tuple[Package, str]],
    partial: dict[str, list[dict]],
    console: Console,
) -> tuple[dict[int, str] | None, UpstreamError | None]:
    """Merge one response; return its page tokens, or the failure that makes its queries incomplete."""
    try:
        return collect_batch_vulns(read_json(), query_indexes, pkg_index, partial, console), None
    except (ValueError, KeyError, AttributeError, TypeError) as exc:
        record_enrichment_source("osv", "failure", error=f"parse error: {type(exc).__name__}")
        console.print("  [red]✗[/red] OSV returned an invalid or incomplete response")
        return None, UpstreamInvalidResponseError("osv", f"parse error: {type(exc).__name__}")


def pagination_limit_failure(console: Console) -> UpstreamError:
    console.print("  [red]✗[/red] OSV returned more result pages than the scan follows")
    record_enrichment_source("osv", "failure", error="pagination limit reached")
    return UpstreamInvalidResponseError("osv", "pagination limit reached")


def query_failures(
    indexes: list[int], pkg_index: dict[int, tuple[Package, str]], failure: UpstreamError
) -> list[tuple[str, str, UpstreamError]]:
    """One lookup error per package behind the failed queries."""
    return [(pkg_index[idx][0].name, pkg_index[idx][0].ecosystem, failure) for idx in indexes if idx in pkg_index]
