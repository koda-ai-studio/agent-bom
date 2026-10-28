"""Am I affected by CVE-X?" answered from stored inventory, per asset.

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) names ``php:php``. Three stored
image scans: the official php 8.3.30 runtime (affected, patch to 8.3.36), the
official php 8.3.36 runtime (not affected) and a Debian image whose
``php8.2-cli`` comes from the distribution (possibly affected: only the
distribution's advisory can decide a backported package).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_bom.db.schema import init_db, open_existing_db_readonly
from agent_bom.db.sync import sync_db
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.scanners.advisory_affected import (
    AffectedCursorError,
    affected_answer,
    feed_advisory_from_db,
    page_answer,
)
from agent_bom.scanners.operator_advisory import OperatorAdvisory

_FIXTURES = Path(__file__).parent / "fixtures"
_REPORTS = _FIXTURES / "php2shell" / "affected-reports.json"
_ADVISORY = _FIXTURES / "php2shell" / "operator-advisory.json"
_NVD_PAGE = _FIXTURES / "nvd" / "php2shell_cves_page.json"
_DISTRO_DETAIL = "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory"


def _reports() -> list[dict]:
    return json.loads(_REPORTS.read_text())


def _advisory() -> OperatorAdvisory:
    return OperatorAdvisory.model_validate(json.loads(_ADVISORY.read_text()))


def _brief(rows: list[dict]) -> list[tuple]:
    return [(r["asset_label"], r["package"]["name"], r["installed_version"], r["fixed_version"], r["verdict"]) for r in rows]


def test_php2shell_answer_per_asset() -> None:
    answer = affected_answer(_advisory(), _reports(), source="operator_advisory")

    assert answer["summary"] == {
        "affected": 1,
        "possibly_affected": 1,
        "not_affected": 1,
        "clean_scanned": 1,
        "assets_examined": 3,
        "reports_examined": 3,
    }
    assert answer["complete"] is True
    assert _brief(answer["rows"]) == [
        ("php:8.3.30-cli", "php", "8.3.30", "8.3.36", "affected"),
        ("abtest/php-debian:12", "php8.2-cli", "8.2.29-1~deb12u1", None, "possibly_affected"),
        ("php:8.3.36-cli", "php", "8.3.36", None, "not_affected"),
    ]
    affected, distro, clean = answer["rows"]
    assert affected["provenance"] == "operator_advisory" and affected["verdict_reason"] is None
    assert affected["scan_id"] == "scan-php-8.3.30" and affected["last_observed_at"] == "2026-10-22T08:00:00+00:00"
    assert distro["verdict_reason"] == "distro_backport_unverified" and distro["verdict_detail"] == _DISTRO_DETAIL
    assert answer["advisory"] == {
        "id": "CVE-2026-109618",
        "aliases": ["CVE-2026-109619"],
        "summary": "php2shell: unauthenticated remote code execution in PHP core",
        "severity": "critical",
        "severity_source": "operator_advisory",
        "cvss_score": None,
        "source": "operator_advisory",
        "published_at": "2026-10-21T00:00:00+00:00",
        "fixed_versions": ["8.2.35", "8.3.36", "8.4.27", "8.5.12"],
    }


def test_graph_node_ids_exist_in_the_scan_graph() -> None:
    reports = {report["scan_id"]: report for report in _reports()}
    for row in affected_answer(_advisory(), list(reports.values()))["rows"]:
        graph = build_unified_graph_from_report(reports[row["scan_id"]], scan_id=row["scan_id"])
        ids = {node.id for node in graph.nodes.values()}
        assert row["graph"]["package_node_id"] in ids
        assert row["graph"]["server_node_id"] in ids
        assert row["graph"]["agent_node_id"] in ids


def test_package_already_carrying_the_feed_record_is_affected_by_scan() -> None:
    reports = _reports()
    php = reports[0]["agents"][0]["mcp_servers"][0]["packages"][0]
    php["vulnerabilities"] = [{"id": "CVE-2026-109618", "severity": "critical", "fixed_version": "8.3.36", "source": "nvd"}]
    rows = affected_answer(_advisory(), reports)["rows"]
    assert [(r["verdict"], r["provenance"], r["fixed_version"]) for r in rows if r["verdict"] == "affected"] == [
        ("affected", "scan", "8.3.36")
    ]


def test_nothing_scanned_is_incomplete_never_clean() -> None:
    answer = affected_answer(_advisory(), [])
    assert answer["complete"] is False
    assert answer["summary"]["assets_examined"] == 0 and answer["rows"] == []


def test_pages_carry_generation_and_refuse_a_changed_snapshot() -> None:
    answer = affected_answer(_advisory(), _reports())
    first = page_answer(answer, tenant_id="t1", limit=2)
    assert [r["verdict"] for r in first["rows"]] == ["affected", "possibly_affected"]
    assert first["has_more"] is True and first["next_cursor"]
    second = page_answer(answer, tenant_id="t1", limit=2, cursor=first["next_cursor"])
    assert [r["verdict"] for r in second["rows"]] == ["not_affected"] and second["next_cursor"] is None
    assert second["summary"] == first["summary"]

    reports = _reports()
    reports.pop()
    changed = affected_answer(_advisory(), reports)
    with pytest.raises(AffectedCursorError) as stale:
        page_answer(changed, tenant_id="t1", limit=2, cursor=first["next_cursor"])
    assert stale.value.kind == "stale"
    with pytest.raises(AffectedCursorError) as other_tenant:
        page_answer(answer, tenant_id="t2", limit=2, cursor=first["next_cursor"])
    # A cursor minted for another tenant is malformed (422) on every route, never "stale".
    assert other_tenant.value.kind == "malformed"
    with pytest.raises(AffectedCursorError) as malformed:
        page_answer(answer, tenant_id="t1", limit=2, cursor="not-a-cursor")
    assert malformed.value.kind == "malformed"


def test_verdict_and_search_filters_keep_summary_whole() -> None:
    answer = affected_answer(_advisory(), _reports())
    page = page_answer(answer, tenant_id="t1", verdict="possibly_affected")
    assert _brief(page["rows"]) == [("abtest/php-debian:12", "php8.2-cli", "8.2.29-1~deb12u1", None, "possibly_affected")]
    assert page["summary"]["affected"] == 1
    assert [r["package"]["name"] for r in page_answer(answer, tenant_id="t1", q="8.3.36")["rows"]] == ["php"]
    with pytest.raises(ValueError):
        page_answer(answer, tenant_id="t1", verdict="safe")


@pytest.fixture()
def nvd_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    page = json.loads(_NVD_PAGE.read_text())

    def fake(url: str, **_: object) -> dict:
        return page if "lastModStartDate" in url else {"totalResults": 0, "vulnerabilities": []}

    db_path = tmp_path / "vulns.db"
    with patch("agent_bom.http_client.fetch_json", side_effect=fake), patch("time.sleep"):
        sync_db(path=db_path, sources=["nvd"], nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    init_db(db_path).close()
    return db_path


def test_nvd_only_cve_resolves_from_cpe_ranges(nvd_db: Path) -> None:
    conn = open_existing_db_readonly(nvd_db)
    try:
        advisory = feed_advisory_from_db(conn, "CVE-2026-109618")
        by_alias = feed_advisory_from_db(conn, "cve-2026-109619")
        assert feed_advisory_from_db(conn, "CVE-2026-0000001") is None
    finally:
        conn.close()
    assert advisory is not None and advisory.id == "CVE-2026-109618"
    assert by_alias is not None and by_alias.id == "CVE-2026-109619"
    answer = affected_answer(advisory, _reports(), source="feed")
    assert answer["advisory"]["source"] == "feed"
    assert _brief(answer["rows"]) == [
        ("php:8.3.30-cli", "php", "8.3.30", "8.3.36", "affected"),
        ("abtest/php-debian:12", "php8.2-cli", "8.2.29-1~deb12u1", None, "possibly_affected"),
        ("php:8.3.36-cli", "php", "8.3.36", None, "not_affected"),
    ]
    assert answer["rows"][0]["provenance"] == "feed"
