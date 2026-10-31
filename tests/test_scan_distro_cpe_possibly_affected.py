"""A plain scan reports distro packages of a CPE product as possibly affected.

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) reaches the local DB only as NVD
CPE ranges on ``php:php``. Debian ships php as ``php8.2-*`` built from source
``php8.2`` with backported fixes, so an upstream range can neither confirm nor
clear it: without a distro record the scan says "possibly affected, verify the
distribution's advisory"; with one, the distro record decides. The official
runtime (``generic`` + CPE) keeps its upstream verdict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_db
from agent_bom.models import Package
from agent_bom.scanners.local_advisories import _scan_packages_db_conn

_FIXTURE = Path(__file__).parent / "fixtures" / "nvd" / "php2shell_cves_page.json"
_PHP2SHELL = {"CVE-2026-109618", "CVE-2026-109619"}
_DETAIL = "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory"


def _nvd(url: str, *, timeout: float = 60, headers: dict | None = None) -> dict:
    if "lastModStartDate" in parse_qs(urlparse(url).query):
        return json.loads(_FIXTURE.read_text())
    return {"totalResults": 0, "vulnerabilities": []}


@pytest.fixture()
def nvd_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    path = tmp_path / "vulns.db"
    with patch("agent_bom.http_client.fetch_json", side_effect=_nvd), patch("time.sleep"):
        sync_db(path=path, sources=["nvd"], nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    conn = init_db(path)
    yield conn
    conn.close()


def _add_debian_record(conn) -> None:
    conn.execute(
        "INSERT INTO vulns (id, summary, severity, source, aliases) VALUES (?, ?, 'unknown', 'debian-tracker', ?)",
        ("DEBIAN-CVE-2026-109618", "php8.2 OOM longjmp RCE", "CVE-2026-109618"),
    )
    conn.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) VALUES (?, ?, ?, '0', ?, '')",
        ("DEBIAN-CVE-2026-109618", "debian:12", "php8.2", "8.2.35-1~deb12u1"),
    )
    conn.commit()


def _deb(name: str, version: str, source: str = "php8.2") -> Package:
    return Package(
        name=name,
        version=version,
        ecosystem="deb",
        purl=f"pkg:deb/debian/{name}@{version}?distro=debian-12",
        source_package=source,
        distro_name="debian",
        distro_version="12",
    )


def _runtime(version: str) -> Package:
    return Package(name="php", version=version, ecosystem="generic", cpe=f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*")


def test_debian_php_without_distro_record_is_possibly_affected_not_silent(nvd_db) -> None:
    cli, common, defaults = (
        _deb("php8.2-cli", "8.2.29-1~deb12u1"),
        _deb("php8.2-common", "8.2.29-1~deb12u1"),
        _deb("php-common", "2:93", "php-defaults"),
    )
    _scan_packages_db_conn(nvd_db, [cli, common, defaults], set())

    assert cli.vulnerabilities == [] and common.vulnerabilities == []
    rows = {row["id"]: row for row in cli.possibly_affected}
    assert set(rows) == _PHP2SHELL
    assert rows["CVE-2026-109618"] == {
        "id": "CVE-2026-109618",
        "verdict": "possibly_affected",
        "reason": "distro_backport_unverified",
        "detail": _DETAIL,
        "cpe_product": "php:php",
        "upstream_version": "8.2.29",
        "upstream_fixed_version": "8.2.35",
        "severity": "critical",
        "cvss_score": 9.8,
        "summary": rows["CVE-2026-109618"]["summary"],
        "source": "nvd",
    }
    assert rows["CVE-2026-109618"]["summary"]
    assert {row["id"] for row in common.possibly_affected} == _PHP2SHELL
    assert defaults.possibly_affected == [] and defaults.vulnerabilities == []


def test_debian_php_past_the_upstream_fix_is_not_flagged(nvd_db) -> None:
    patched = _deb("php8.2-cli", "8.2.35-1~deb12u1")
    _scan_packages_db_conn(nvd_db, [patched], set())
    assert patched.possibly_affected == [] and patched.vulnerabilities == []


def test_debian_feed_record_decides_affected_with_distro_fix(nvd_db) -> None:
    _add_debian_record(nvd_db)
    cli = _deb("php8.2-cli", "8.2.29-1~deb12u1")
    _scan_packages_db_conn(nvd_db, [cli], set())

    assert [(v.id, v.fixed_version) for v in cli.vulnerabilities] == [("CVE-2026-109618", "8.2.35-1~deb12u1")]
    assert [row["id"] for row in cli.possibly_affected] == ["CVE-2026-109619"]


def test_debian_feed_record_decides_not_affected(nvd_db) -> None:
    _add_debian_record(nvd_db)
    # A backported fix: Debian fixed 8.2.29 in a later revision of the same upstream release.
    nvd_db.execute("UPDATE affected SET fixed = '8.2.29-1~deb12u1' WHERE vuln_id = 'DEBIAN-CVE-2026-109618'")
    nvd_db.commit()
    cli = _deb("php8.2-cli", "8.2.29-1~deb12u1")
    _scan_packages_db_conn(nvd_db, [cli], set())

    assert cli.vulnerabilities == []
    assert [row["id"] for row in cli.possibly_affected] == ["CVE-2026-109619"]


def test_official_runtime_keeps_upstream_verdict(nvd_db) -> None:
    vulnerable, patched = _runtime("8.3.30"), _runtime("8.3.36")
    _scan_packages_db_conn(nvd_db, [vulnerable, patched], set())

    assert {v.id: v.fixed_version for v in vulnerable.vulnerabilities} == {"CVE-2026-109618": "8.3.36", "CVE-2026-109619": "8.3.36"}
    assert vulnerable.possibly_affected == [] and patched.vulnerabilities == [] and patched.possibly_affected == []


def test_batch_path_reports_the_same(nvd_db) -> None:
    filler = [Package(name=f"filler-{i}", version="1.0", ecosystem="pypi") for i in range(60)]
    cli = _deb("php8.2-cli", "8.2.29-1~deb12u1")
    _scan_packages_db_conn(nvd_db, [*filler, cli], set())
    assert {row["id"] for row in cli.possibly_affected} == _PHP2SHELL
    assert cli.vulnerabilities == []


# --- scan_agents end to end, then every output surface ---------------------------------------

_RULE = "agent-bom/possibly-affected"


def _scanned_report(nvd_db, monkeypatch: pytest.MonkeyPatch):
    import asyncio

    from agent_bom.db import schema
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
    from agent_bom.scanners import scan_agents
    from agent_bom.scanners.scan_options import ScanOptions

    # A synced DB also holds the distro feed; an unrelated Debian record makes debian:12 covered offline.
    nvd_db.execute("INSERT INTO vulns (id, summary, severity, source) VALUES ('DEBIAN-CVE-2026-0001', 'other', 'low', 'osv')")
    nvd_db.execute(
        "INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected) "
        "VALUES ('DEBIAN-CVE-2026-0001', 'debian:12', 'openssl', '0', '3.0.1-1', '')"
    )
    nvd_db.commit()
    db_file = Path(nvd_db.execute("PRAGMA database_list").fetchone()[2])
    monkeypatch.setattr(schema, "DB_PATH", db_file)
    agents = [
        Agent(
            name=f"image:abtest/php-debian:{tag}",
            agent_type=AgentType.CUSTOM,
            config_path=f"docker://abtest/php-debian:{tag}",
            mcp_servers=[MCPServer(name=f"abtest/php-debian:{tag}", packages=[_deb("php8.2-cli", "8.2.29-1~deb12u1")])],
        )
        for tag in ("a", "b")
    ]
    radii = asyncio.run(scan_agents(agents, show_scan_banner=False, options=ScanOptions(offline=True)))
    return AIBOMReport(scan_id="possibly-affected-scan", agents=agents, blast_radii=radii)


def test_scan_agents_carries_possibly_affected_to_every_instance_and_counts_nothing(nvd_db, monkeypatch) -> None:
    report = _scanned_report(nvd_db, monkeypatch)
    assert report.blast_radii == []
    assert report.total_vulnerabilities == 0
    for agent in report.agents:
        assert {row["id"] for row in agent.mcp_servers[0].packages[0].possibly_affected} == _PHP2SHELL


def test_json_report_has_structured_possibly_affected(nvd_db, monkeypatch) -> None:
    from agent_bom.output import to_json

    doc = to_json(_scanned_report(nvd_db, monkeypatch))
    assert doc["summary"]["total_vulnerabilities"] == 0
    rows = {(row["id"], row["package"]["name"]): row for row in doc["possibly_affected"]}
    assert set(rows) == {(cve, "php8.2-cli") for cve in _PHP2SHELL}
    row = rows[("CVE-2026-109618", "php8.2-cli")]
    assert row["verdict"] == "possibly_affected" and row["reason"] == "distro_backport_unverified"
    assert row["detail"] == _DETAIL
    assert row["package"]["version"] == "8.2.29-1~deb12u1" and row["package"]["ecosystem"] == "deb"
    assert row["agents"] == ["image:abtest/php-debian:a", "image:abtest/php-debian:b"]
    package_json = doc["agents"][0]["mcp_servers"][0]["packages"][0]
    assert {entry["id"] for entry in package_json["possibly_affected"]} == _PHP2SHELL
    assert package_json["vulnerabilities"] == []


def test_sarif_has_note_level_possibly_affected_results(nvd_db, monkeypatch) -> None:
    from agent_bom.output.sarif import to_sarif

    run = to_sarif(_scanned_report(nvd_db, monkeypatch))["runs"][0]
    rule = next(rule for rule in run["tool"]["driver"]["rules"] if rule["id"] == _RULE)
    assert rule["defaultConfiguration"]["level"] == "note"
    assert "security-severity" not in rule.get("properties", {})
    results = [result for result in run["results"] if result["ruleId"] == _RULE]
    assert all(result["ruleId"] == _RULE for result in run["results"])
    assert {result["properties"]["cve_id"] for result in results} == _PHP2SHELL
    result = next(r for r in results if r["properties"]["cve_id"] == "CVE-2026-109618")
    assert result["level"] == "note" and result["kind"] == "review"
    assert _DETAIL in result["message"]["text"] and "distro_backport_unverified" in result["message"]["text"]
    assert result["properties"]["verdict"] == "possibly_affected"
    assert result["properties"]["reason"] == "distro_backport_unverified"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docker://abtest/php-debian:a"
    assert len({r["fingerprints"]["agent-bom/v1"] for r in results}) == len(results)


def test_cyclonedx_has_in_triage_vulnerabilities(nvd_db, monkeypatch) -> None:
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    cdx = to_cyclonedx(_scanned_report(nvd_db, monkeypatch))
    refs = {component["bom-ref"] for component in cdx["components"] if component.get("name") == "php8.2-cli"}
    entries = {entry["id"]: entry for entry in cdx["vulnerabilities"]}
    assert set(entries) == _PHP2SHELL
    entry = entries["CVE-2026-109618"]
    assert entry["analysis"]["state"] == "in_triage"
    assert _DETAIL in entry["analysis"]["detail"]
    assert {affected["ref"] for affected in entry["affects"]} <= refs and entry["affects"]
    props = {prop["name"]: prop["value"] for prop in entry["properties"]}
    assert props["agent-bom:verdict"] == "possibly_affected"
    assert props["agent-bom:reason"] == "distro_backport_unverified"
    assert "recommendation" not in entry
    total = next(p["value"] for p in cdx["metadata"]["properties"] if p["name"] == "agent-bom:total-vulnerabilities")
    assert total == "0"


def test_html_report_has_possibly_affected_rows(nvd_db, monkeypatch) -> None:
    from agent_bom.output.html import to_html

    page = to_html(_scanned_report(nvd_db, monkeypatch))
    match = re.search(r'<section id="possibly-affected"([^>]*)>(.*?)</section>', page, re.DOTALL)
    assert match is not None
    assert 'data-tab="findings"' in match[1]
    assert 'role="tabpanel"' in match[1]
    section = match[2]
    assert "Possibly affected" in section and "verify distro advisory" in section
    assert section.count('<tr data-verdict="possibly_affected">') == 2
    assert "CVE-2026-109618" in section and "php8.2-cli" in section and "8.2.29-1~deb12u1" in section
    assert "verify against the distribution&#x27;s advisory" in section or "verify against the distribution's advisory" in section


def test_terminal_shows_possibly_affected_section(nvd_db, monkeypatch) -> None:
    from rich.console import Console

    import agent_bom.output as output
    from agent_bom.output.compact import print_compact_graph_findings

    report = _scanned_report(nvd_db, monkeypatch)
    console = Console(record=True, width=200)
    monkeypatch.setattr(output, "console", console)
    print_compact_graph_findings(report)
    text = console.export_text()
    assert "Possibly affected — verify distro advisory (2)" in text
    assert "CVE-2026-109618" in text and "php8.2-cli 8.2.29-1~deb12u1" in text
    assert "verify against the distribution's advisory" in text
    assert "not counted as vulnerabilities" in text
