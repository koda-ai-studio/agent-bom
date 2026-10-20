"""The CISA KEV join every scan runs, independent of ``--enrich``."""

from __future__ import annotations

import asyncio
import logging

from agent_bom import enrichment
from agent_bom.compliance_utils import apply_effective_blast_radius_tags
from agent_bom.config import kev_default_join_mode
from agent_bom.models import BlastRadius
from agent_bom.scanners.enrichment_apply import join_kev_status

_logger = logging.getLogger(__name__)

#: Network budget for the KEV join a plain scan runs; ``--enrich`` keeps its own.
_DEFAULT_KEV_JOIN_TIMEOUT_SECONDS = 10.0


def join_default_kev_catalog(blast_radii: list[BlastRadius], *, offline: bool) -> int:
    """Join CISA KEV onto a scan that ran without ``--enrich``; return KEV findings.

    KEV drives fix-first priority and the KEV counts, so it is not an opt-in.
    The join is one cached catalog read (24h TTL; offline reads only the local
    cache or air-gap bundle). It never fails the scan: when the catalog is
    unavailable each vulnerability is marked ``kev_status="unknown"``.
    ``AGENT_BOM_KEV_DEFAULT_JOIN=cache`` restricts it to local caches,
    ``off`` disables it.
    """
    if not blast_radii:
        return 0
    mode = kev_default_join_mode()
    if mode in {"0", "off", "false", "no"}:
        return 0
    vulns = list({id(br.vulnerability): br.vulnerability for br in blast_radii}.values())
    already_listed = {id(v) for v in vulns if v.is_kev}
    try:
        asyncio.run(
            enrichment.join_kev_catalog(vulns, offline=offline or mode == "cache", timeout=_DEFAULT_KEV_JOIN_TIMEOUT_SECONDS),
        )
    except Exception as exc:  # noqa: BLE001 - KEV is advisory context; the scan result stands
        _logger.warning("CISA KEV catalog join unavailable: %s", type(exc).__name__)
        join_kev_status(vulns, {})
    if any(v.is_kev and id(v) not in already_listed for v in vulns):
        for br in blast_radii:
            br.calculate_risk_score()
            apply_effective_blast_radius_tags(br)
        blast_radii.sort(key=lambda br: br.risk_score or 0.0, reverse=True)
    return sum(1 for br in blast_radii if br.vulnerability.is_kev)
