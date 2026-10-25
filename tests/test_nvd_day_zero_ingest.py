"""Day-zero NVD ingestion: NVD-only CVEs and their CPE ranges reach the local DB.

The fixture is a trimmed, recorded NVD 2.0 response for CVE-2026-109618 and
CVE-2026-109619 (PHP core RCE). It keeps the php:php ranges plus unrelated
Siemens and PAN-OS nodes so vendor/product scoping is exercised. No test here
touches the network.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_db
from agent_bom.db.sync_nvd_window import NvdRateLimiter
from agent_bom.models import Package
from agent_bom.scanners.local_advisories import _scan_packages_db_conn

_FIXTURE = Path(__file__).parent / "fixtures" / "nvd" / "php2shell_cves_page.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PHP2SHELL = {"CVE-2026-109618", "CVE-2026-109619"}


def _page() -> dict:
    return json.loads(_FIXTURE.read_text())


class _RecordingNvd:
    """Serve the recorded window page; ``cveId`` backfill lookups return nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        self.calls.append((url, dict(headers or {})))
        query = parse_qs(urlparse(url).query)
        if "lastModStartDate" in query:
            return _page()
        return {"totalResults": 0, "vulnerabilities": []}


def _php_runtime(version: str) -> Package:
    return Package(
        name="php",
        version=version,
        ecosystem="generic",
        purl=f"pkg:generic/php/php@{version}",
        cpe=f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
    )


def _sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str | None) -> tuple[Path, _RecordingNvd, dict]:
    if key is None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVD_API_KEY", key)
    db_path = tmp_path / "vulns.db"
    fake = _RecordingNvd()
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep"):
        results = sync_db(path=db_path, sources=["nvd"], nvd_url=_NVD_URL)
    return db_path, fake, results


def _nvd_meta(db_path: Path) -> dict:
    conn = init_db(db_path)
    try:
        row = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'nvd'").fetchone()
        return json.loads(row[0])
    finally:
        conn.close()


@pytest.mark.parametrize("key", [None, "nvd-test-key"], ids=["keyless", "keyed"])
def test_db_update_nvd_ingests_nvd_only_cves_with_cpe_ranges(tmp_path, monkeypatch, key) -> None:
    db_path, fake, results = _sync(tmp_path, monkeypatch, key)

    window_calls = [call for call in fake.calls if "lastModStartDate" in call[0]]
    assert window_calls, "db update --source nvd must page the lastModified window"
    assert results["nvd"] >= 2

    conn = init_db(db_path)
    try:
        rows = {row["id"]: row for row in conn.execute("SELECT * FROM vulns WHERE id LIKE 'CVE-2026-1096%'")}
        assert set(rows) == _PHP2SHELL
        assert rows["CVE-2026-109618"]["severity"] == "critical"
        assert rows["CVE-2026-109618"]["cvss_score"] == 9.8
        assert rows["CVE-2026-109618"]["published"].startswith("2026-10-21")
        assert rows["CVE-2026-109618"]["modified"].startswith("2026-10-23")
        php_ranges = conn.execute(
            "SELECT version_start, version_end FROM cpe_matches WHERE cve_id = 'CVE-2026-109618' AND vendor = 'php' AND product = 'php' "
            "ORDER BY version_start"
        ).fetchall()
        assert [tuple(r) for r in php_ranges] == [
            ("7.3.0", "8.2.35"),
            ("8.3.0", "8.3.36"),
            ("8.4.0", "8.4.27"),
            ("8.5.0", "8.5.12"),
        ]
    finally:
        conn.close()

    meta = _nvd_meta(db_path)
    assert meta["status"] == "synced"
    assert meta["api_key_used"] is (key is not None)


def test_keyless_window_is_bounded_and_sends_no_key(tmp_path, monkeypatch) -> None:
    db_path, fake, _ = _sync(tmp_path, monkeypatch, None)
    for url, headers in fake.calls:
        assert "apiKey" not in headers
        assert "apiKey" not in url
    meta = _nvd_meta(db_path)
    assert meta["lookback_days"] <= 30


def test_keyed_sync_sends_key_only_as_header_and_never_logs_or_stores_it(tmp_path, monkeypatch, caplog) -> None:
    secret = "-".join(["nvd", "key", "marker", "7f3a"])
    caplog.set_level(logging.DEBUG)
    db_path, fake, _ = _sync(tmp_path, monkeypatch, secret)

    assert fake.calls
    for url, headers in fake.calls:
        assert urlparse(url).hostname == "services.nvd.nist.gov"
        assert secret not in url
        assert headers.get("apiKey") == secret
    assert secret not in caplog.text
    conn = init_db(db_path)
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    assert secret not in dump


def test_php_runtime_matches_nvd_cpe_range_offline_after_sync(tmp_path, monkeypatch) -> None:
    db_path, _, _ = _sync(tmp_path, monkeypatch, None)
    conn = init_db(db_path)
    try:
        vulnerable = _php_runtime("8.3.30")
        patched = _php_runtime("8.3.36")
        _scan_packages_db_conn(conn, [vulnerable, patched], set())
    finally:
        conn.close()

    hits = {v.id: v for v in vulnerable.vulnerabilities}
    assert set(hits) == _PHP2SHELL
    assert hits["CVE-2026-109618"].fixed_version == "8.3.36"
    assert patched.vulnerabilities == []


@pytest.mark.parametrize("status", [429, 403])
def test_rate_limited_window_is_partial_and_keeps_checkpoint(tmp_path, monkeypatch, status) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    request = httpx.Request("GET", _NVD_URL)

    def limited(url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        if "lastModStartDate" in url:
            raise httpx.HTTPStatusError("limited", request=request, response=httpx.Response(status, request=request))
        return {"totalResults": 0, "vulnerabilities": []}

    db_path = tmp_path / "vulns.db"
    with patch("agent_bom.http_client.fetch_json", side_effect=limited), patch("time.sleep"):
        sync_db(path=db_path, sources=["nvd"], nvd_url=_NVD_URL)

    meta = _nvd_meta(db_path)
    assert meta["status"] == "partial"
    assert meta["partial_reason"] == "rate_limited"
    assert meta["last_modified_end"] == meta["last_modified_start"]


def test_timeout_window_is_partial(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    def slow(url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        raise httpx.ReadTimeout("slow")

    db_path = tmp_path / "vulns.db"
    with patch("agent_bom.http_client.fetch_json", side_effect=slow), patch("time.sleep"):
        sync_db(path=db_path, sources=["nvd"], nvd_url=_NVD_URL)
    meta = _nvd_meta(db_path)
    assert meta["status"] == "partial"
    assert meta["partial_reason"] == "timeout"


def test_rate_limiter_keeps_five_requests_per_rolling_30s() -> None:
    clock = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    limiter = NvdRateLimiter(max_requests=5, window_seconds=30.0, clock=lambda: clock[0], sleep=sleep)
    stamps = []
    for _ in range(11):
        limiter.acquire()
        stamps.append(clock[0])
        clock[0] += 0.1
    for i in range(len(stamps)):
        in_window = [s for s in stamps if stamps[i] - 30.0 < s <= stamps[i]]
        assert len(in_window) <= 5
    assert slept, "the sixth request must wait for the window to roll"


def test_rate_limiter_honours_retry_after() -> None:
    clock = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    limiter = NvdRateLimiter(max_requests=50, window_seconds=30.0, clock=lambda: clock[0], sleep=sleep)
    limiter.acquire()
    limiter.defer(12.0)
    limiter.acquire()
    assert slept and slept[0] >= 12.0


@pytest.mark.real_vuln_db_sync
def test_db_update_cli_reports_partial_nvd_window(tmp_path, monkeypatch) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._db import db_cmd

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    db_path = tmp_path / "vulns.db"

    def limited(url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        request = httpx.Request("GET", _NVD_URL)
        raise httpx.HTTPStatusError("limited", request=request, response=httpx.Response(429, request=request))

    with patch("agent_bom.http_client.fetch_json", side_effect=limited), patch("time.sleep"):
        result = CliRunner().invoke(db_cmd, ["update", "--source", "nvd", "--path", str(db_path)])

    assert result.exit_code == 0, result.output
    assert "nvd: PARTIAL (rate_limited)" in result.output
    assert "not a complete NVD window" in result.output


def test_unscored_nvd_cve_is_matchable_and_not_refetched_by_the_backfill(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    page = _page()
    for item in page["vulnerabilities"]:
        item["cve"].pop("metrics", None)
        item["cve"].pop("weaknesses", None)
    calls: list[str] = []

    def fetch(url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
        calls.append(url)
        return page if "lastModStartDate" in url else {"totalResults": 0, "vulnerabilities": []}

    db_path = tmp_path / "vulns.db"
    with patch("agent_bom.http_client.fetch_json", side_effect=fetch), patch("time.sleep"):
        sync_db(path=db_path, sources=["nvd"], nvd_url=_NVD_URL)

    assert not [url for url in calls if "cveId=" in url], "the backfill re-requested CVEs the window just read from NVD"
    conn = init_db(db_path)
    try:
        severities = {row[0]: row[1] for row in conn.execute("SELECT id, severity FROM vulns WHERE id LIKE 'CVE-2026-1096%'")}
        runtime = _php_runtime("8.3.30")
        _scan_packages_db_conn(conn, [runtime], set())
    finally:
        conn.close()
    assert severities == {"CVE-2026-109618": "unknown", "CVE-2026-109619": "unknown"}
    assert {v.id for v in runtime.vulnerabilities} == _PHP2SHELL
