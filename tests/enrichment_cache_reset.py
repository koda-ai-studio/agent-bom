"""Test-only reset for the process-wide KEV / NVD / EPSS enrichment caches."""

from __future__ import annotations


def reset_enrichment_caches() -> None:
    """Drop the in-memory and on-disk KEV / NVD / EPSS caches for this process."""
    from agent_bom import enrichment

    enrichment._kev_cache = None
    enrichment._kev_cache_time = None
    enrichment._nvd_file_cache.clear()
    enrichment._epss_file_cache.clear()
    enrichment._enrichment_cache_loaded = False
    enrichment._offline_bundle_epss_loaded = False
    cache_dir = enrichment._ENRICHMENT_CACHE_DIR
    for path in (enrichment._KEV_CACHE_FILE, cache_dir / "nvd_cache.json", cache_dir / "epss_cache.json"):
        path.unlink(missing_ok=True)
