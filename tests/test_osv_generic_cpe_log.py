"""Generic components skip OSV with an accurate, non-alarming log line."""

from __future__ import annotations

import asyncio
import logging
import sqlite3

from rich.console import Console

from agent_bom.models import Package
from agent_bom.scanners import _NON_OSV_ECOSYSTEMS
from agent_bom.scanners.osv import query_osv_batch_impl
from agent_bom.scanners.package_matching import _osv_ecosystems_for_package
from agent_bom.scanners.package_preparation import _select_scannable_packages

PHP_CPE = "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"


def _run(packages: list[Package]) -> None:
    async def _never(*_a, **_k):
        raise AssertionError("no network query expected")

    async def _passthrough(results):
        return results

    asyncio.run(
        query_osv_batch_impl(
            packages,
            console=Console(quiet=True),
            get_scan_cache=lambda: None,
            get_api_semaphore=lambda: asyncio.Semaphore(1),
            bump_scan_perf=lambda _k, _n: None,
            enrich_results_if_needed_fn=_passthrough,
            record_scan_warning=lambda _m: None,
            osv_ecosystems_for_package=_osv_ecosystems_for_package,
            non_osv_ecosystems=_NON_OSV_ECOSYSTEMS,
            create_client_fn=_never,
            request_with_retry_fn=_never,
        )
    )


def _osv_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "agent_bom.scanners.osv" and "generic/php" in r.getMessage()]


def test_generic_package_with_cpe_logs_cpe_route_at_debug(caplog) -> None:
    pkg = Package(name="php", version="8.1.2", ecosystem="generic", cpe=PHP_CPE)
    with caplog.at_level(logging.DEBUG, logger="agent_bom.scanners.osv"):
        _run([pkg])
    records = _osv_records(caplog)
    assert [r.levelno for r in records] == [logging.DEBUG]
    message = records[0].getMessage()
    assert "unknown ecosystem" not in message
    assert "CPE" in message


def test_generic_package_without_cpe_warns_that_nothing_can_match_it(caplog) -> None:
    pkg = Package(name="php", version="8.1.2", ecosystem="generic")
    with caplog.at_level(logging.DEBUG, logger="agent_bom.scanners.osv"):
        _run([pkg])
    records = _osv_records(caplog)
    assert [r.levelno for r in records] == [logging.WARNING]
    assert "no CPE" in records[0].getMessage()


def test_truly_unknown_ecosystem_still_warns(caplog) -> None:
    pkg = Package(name="somelib", version="1.0.0", ecosystem="pacman")
    with caplog.at_level(logging.WARNING, logger="agent_bom.scanners.osv"):
        _run([pkg])
    assert any("unknown ecosystem" in r.getMessage() for r in caplog.records)


def test_generic_cpe_package_stays_in_the_local_db_and_matches_by_cpe(monkeypatch) -> None:
    from agent_bom.scanners import local_advisories

    pkg = Package(name="php", version="8.1.2", ecosystem="generic", cpe=PHP_CPE)
    assert _select_scannable_packages([pkg]) == [pkg]

    seen: list[tuple[str, str]] = []

    def _fake_cpe_lookup(_conn, product, version, *, vendor=None, target_sw=None):
        seen.append((vendor or "", product))
        return []

    monkeypatch.setattr("agent_bom.db.lookup.cpe_lookup_package", _fake_cpe_lookup)
    local_advisories._attach_cpe_candidates(sqlite3.connect(":memory:"), pkg, ["php"], [], db_hit=False)
    assert seen == [("php", "php")]
