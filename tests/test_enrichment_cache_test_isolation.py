"""Process-global enrichment caches must not carry one test's catalog into the next.

A scan that reaches the live CISA KEV feed keeps the catalog in memory and in
``kev_cache.json`` under the per-process state dir for 24 hours. Every later
``--offline`` scan on the same worker then joins that catalog, so the demo's
KEV dates (and every digest over them) depended on which tests shared the
worker.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

import agent_bom.cli  # noqa: F401  # agent_bom.enrichment cannot be the first agent_bom import (import cycle)
from agent_bom import enrichment
from tests.enrichment_cache_reset import reset_enrichment_caches

_LIVE_LIKE_KEV = {"CVE-2023-4863": {"date_added": "2023-09-13", "due_date": "2023-10-04"}}


def _leave_kev_catalog_behind() -> None:
    enrichment._kev_cache = dict(_LIVE_LIKE_KEV)
    enrichment._kev_cache_time = datetime.now(timezone.utc)
    enrichment._KEV_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    enrichment._KEV_CACHE_FILE.write_text(json.dumps({"_cached_at": time.time(), "data": _LIVE_LIKE_KEV}))


def _leave_nvd_epss_caches_behind() -> None:
    enrichment._nvd_file_cache["CVE-2023-4863"] = {"_cached_at": time.time()}
    enrichment._epss_file_cache["CVE-2023-4863"] = {"_cached_at": time.time(), "score": 0.9}
    enrichment._enrichment_cache_loaded = True
    for name in ("nvd_cache.json", "epss_cache.json"):
        (enrichment._ENRICHMENT_CACHE_DIR / name).write_text(json.dumps({"CVE-2023-4863": {"_cached_at": time.time()}}))


def test_reset_clears_memory_and_disk_enrichment_caches() -> None:
    _leave_kev_catalog_behind()
    _leave_nvd_epss_caches_behind()

    reset_enrichment_caches()

    assert enrichment._kev_cache is None
    assert enrichment._kev_cache_time is None
    assert not enrichment._KEV_CACHE_FILE.exists()
    assert enrichment._nvd_file_cache == {}
    assert enrichment._epss_file_cache == {}
    assert enrichment._enrichment_cache_loaded is False
    for name in ("nvd_cache.json", "epss_cache.json"):
        assert not (enrichment._ENRICHMENT_CACHE_DIR / name).exists()
    assert enrichment._cached_kev_catalog(offline=True) == enrichment._load_bundled_kev_catalog()


@pytest.mark.parametrize("_run", ["first", "second"])
def test_offline_demo_kev_join_is_independent_of_the_previous_test(_run: str) -> None:
    """Whichever of the pair runs second sees the first one's leftover catalog unless the autouse reset clears it."""
    from agent_bom.output.sarif import to_sarif
    from tests.test_output_render_characterization import _demo_report

    assert enrichment._kev_cache is None
    assert not enrichment._KEV_CACHE_FILE.exists()

    sarif = to_sarif(_demo_report())
    kev_dates = {
        result["properties"]["kev_date_added"]
        for run in sarif["runs"]
        for result in run["results"]
        if result.get("properties", {}).get("kev_date_added")
    }
    assert kev_dates == {"2023-09-27"}, "demo KEV dates must come from the demo advisory seed, not an ambient catalog"

    _leave_kev_catalog_behind()
