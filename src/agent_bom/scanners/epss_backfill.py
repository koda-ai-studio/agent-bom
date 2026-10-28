"""Bounded live EPSS backfill for CVEs the local table and cache left unscored.

``agent-bom scan --enrich`` answers EPSS from three sources, in order: the
local ``epss_scores`` table (``agent-bom db update``), the on-disk enrichment
cache, and api.first.org for whatever is still unscored. The live step is
bounded so one scan never fans out without limit:

* ``EPSS_BACKFILL_BATCH_SIZE`` CVEs per request — the FIRST API accepts a
  comma-separated ``cve=`` list and answers up to 100 rows per call;
* ``EPSS_BACKFILL_MAX_REQUESTS`` requests per scan (2,000 CVEs); CVEs past the
  cap stay unscored and are reported as degraded coverage, never guessed;
* one per-request timeout, independent of the shared client's default.

A cached entry without a usable score is not an answer: it is re-requested
instead of pinning the CVE to ``None`` until the cache entry expires. The
``EpssSourceSummary`` recorded per scan tells the report which source scored
each finding, so ``vuln_data_freshness`` can say where EPSS came from.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from agent_bom.core.errors import UpstreamError, UpstreamInvalidResponseError
from agent_bom.enrichment_posture import record_enrichment_source
from agent_bom.models import Vulnerability
from agent_bom.scanners.enrichment_apply import vuln_cve_ids
from agent_bom.scanners.upstream import upstream_request

_logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BACKFILL_BATCH_SIZE = 100
EPSS_BACKFILL_MAX_REQUESTS = 20
EPSS_BACKFILL_TIMEOUT_SECONDS = 15.0

RequestFn = Callable[..., Awaitable[httpx.Response | None]]


class EpssBackfillCappedError(UpstreamError):
    """The per-scan request cap left CVEs unrequested; a later scan can finish them."""

    kind = "request_cap"
    default_retryable = True


def has_epss_score(entry: object) -> bool:
    """True when a cache or API entry carries a usable probability in ``[0, 1]``."""
    score = entry.get("score") if isinstance(entry, dict) else None
    return isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0.0 <= score <= 1.0


def parse_epss_items(data: dict, scores: dict[str, dict]) -> None:
    """Parse into ``scores`` item by item, so entries before a malformed one are kept."""
    for item in data.get("data", []):
        cve = item.get("cve")
        if not cve:
            continue
        raw_epss = item.get("epss")
        raw_pct = item.get("percentile")
        parsed_score = float(raw_epss) if raw_epss is not None else None
        parsed_pct = float(raw_pct) if raw_pct is not None else None
        if parsed_score is not None and not (0.0 <= parsed_score <= 1.0):
            parsed_score = None
        if parsed_pct is not None and not (0.0 <= parsed_pct <= 100.0):
            parsed_pct = None
        scores[cve] = {"score": parsed_score, "percentile": parsed_pct, "date": item.get("date")}


def unscored_cve_ids(vulnerabilities: list[Vulnerability]) -> list[str]:
    """CVE ids (identity, alias and upstream) of findings that still have no EPSS score."""
    return sorted({cve for vuln in vulnerabilities if vuln.epss_score is None for cve in vuln_cve_ids(vuln)})


@dataclass
class EpssFetchOutcome:
    """What one bounded fetch answered, and from where."""

    scores: dict[str, dict] = field(default_factory=dict)
    cached: set[str] = field(default_factory=set)
    live: set[str] = field(default_factory=set)
    requests: int = 0
    capped: int = 0


def _record_failure(failure: UpstreamError, errors: list[UpstreamError] | None) -> None:
    record_enrichment_source("epss", "failure", error=failure.detail)
    if errors is not None:
        errors.append(failure)


async def fetch_epss_batches(
    cve_ids: list[str],
    client: httpx.AsyncClient,
    *,
    request_fn: RequestFn,
    errors: list[UpstreamError] | None = None,
    max_requests: int = EPSS_BACKFILL_MAX_REQUESTS,
    batch_size: int = EPSS_BACKFILL_BATCH_SIZE,
    timeout: float = EPSS_BACKFILL_TIMEOUT_SECONDS,
) -> EpssFetchOutcome:
    """Ask the FIRST API for *cve_ids* in batches, never more than *max_requests* times.

    Each batch that fails appends one typed error (``affected`` = batch size);
    CVEs the cap leaves unrequested append one ``EpssBackfillCappedError``.
    """
    outcome = EpssFetchOutcome()
    batches = [cve_ids[start : start + batch_size] for start in range(0, len(cve_ids), batch_size)]
    for batch in batches[:max_requests]:
        outcome.requests += 1
        batch_scores: dict[str, dict] = {}
        try:
            params = {"cve": ",".join(batch)}
            response = await upstream_request("epss", request_fn, client, "GET", EPSS_API_URL, params=params, timeout=timeout)
            record_enrichment_source("epss", "success")
            parse_epss_items(response.json(), batch_scores)
        except UpstreamError as failure:
            failure.affected = len(batch)
            _record_failure(failure, errors)
            _logger.warning("EPSS API request failed for %d CVEs (request %d)", len(batch), outcome.requests)
            continue
        except (ValueError, KeyError, AttributeError, TypeError) as exc:
            _record_failure(UpstreamInvalidResponseError("epss", f"parse error: {type(exc).__name__}", affected=len(batch)), errors)
            _logger.warning("EPSS parse error on request %d: %s", outcome.requests, type(exc).__name__)
        outcome.scores.update(batch_scores)
        outcome.live.update(batch_scores)
    skipped = sum(len(batch) for batch in batches[max_requests:])
    if skipped:
        outcome.capped = skipped
        _record_failure(EpssBackfillCappedError("epss", f"live backfill capped at {max_requests} request(s)", affected=skipped), errors)
        _logger.warning("EPSS live backfill capped at %d request(s); %d CVE(s) left unscored this scan", max_requests, skipped)
    return outcome


@dataclass(frozen=True)
class EpssSourceSummary:
    """How many findings each EPSS source scored in this scan."""

    local_table: int
    cache: int
    live_backfill: int
    unscored: int
    requests: int
    capped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "FIRST EPSS",
            "local_table": self.local_table,
            "cache": self.cache,
            "live_backfill": self.live_backfill,
            "unscored": self.unscored,
            "requests": self.requests,
            "capped": self.capped,
        }

    def label(self) -> str:
        return (
            f"EPSS sources: {self.local_table} local table, {self.cache} cache, "
            f"{self.live_backfill} live backfill, {self.unscored} unscored ({self.requests} request(s))"
        )


def summarize_epss_sources(
    vulnerabilities: list[Vulnerability], *, scored_before: set[int], outcome: EpssFetchOutcome
) -> EpssSourceSummary:
    """Attribute every finding's EPSS to the source that answered it.

    *scored_before* holds ``id()`` of findings that already carried a score
    when enrichment started (the local table or the scanner that built them).
    """
    local = cache = live = unscored = 0
    for vuln in vulnerabilities:
        if id(vuln) in scored_before:
            local += 1
        elif vuln.epss_score is None:
            unscored += 1
        elif vuln.epss_cve_id in outcome.live:
            live += 1
        else:
            cache += 1
    return EpssSourceSummary(
        local_table=local, cache=cache, live_backfill=live, unscored=unscored, requests=outcome.requests, capped=outcome.capped
    )


_state = threading.local()


def record_epss_fetch_outcome(outcome: EpssFetchOutcome) -> None:
    _state.outcome = outcome


def last_epss_fetch_outcome() -> EpssFetchOutcome | None:
    return getattr(_state, "outcome", None)


def record_epss_source_summary(summary: EpssSourceSummary) -> None:
    _state.summary = summary


def epss_source_summary() -> EpssSourceSummary | None:
    """The summary of the most recent enrichment on this thread, for the report."""
    return getattr(_state, "summary", None)


def reset_epss_state() -> None:
    _state.outcome = None
    _state.summary = None
