"""Vulnerability-data accuracy of the bundled demo: fix lines, KEV dates, EPSS, risk.

Facts pinned here were checked against the authoritative records:
- GHSA-r683-j2x4-v87g (CVE-2022-0235): ``< 2.6.7`` fixed 2.6.7; ``>= 3.0.0, < 3.1.1`` fixed 3.1.1.
- CISA KEV CVE-2023-4863: dateAdded 2023-09-13, dueDate 2023-10-04.
"""

from __future__ import annotations

from collections import Counter
from functools import cache
from typing import Any

import pytest

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.demo_advisories import seed_demo_advisories


@pytest.mark.parametrize(("version", "fixed"), [("2.6.1", "2.6.7"), ("3.1.0", "3.1.1")])
def test_demo_node_fetch_fix_stays_on_the_installed_major(tmp_path, version, fixed):
    conn = init_db(tmp_path / "demo.db")
    seed_demo_advisories(conn)
    matches = [v for v in lookup_package(conn, "npm", "node-fetch", version) if v.id == "CVE-2022-0235"]
    conn.close()
    assert [m.fixed_version for m in matches] == [fixed]


@pytest.mark.parametrize("version", ["2.6.7", "3.1.1"])
def test_demo_node_fetch_fixed_releases_are_clean(tmp_path, version):
    conn = init_db(tmp_path / "demo.db")
    seed_demo_advisories(conn)
    assert not [v for v in lookup_package(conn, "npm", "node-fetch", version) if v.id == "CVE-2022-0235"]
    conn.close()


def test_demo_kev_dates_match_the_cisa_catalog(tmp_path):
    conn = init_db(tmp_path / "demo.db")
    seed_demo_advisories(conn)
    (match,) = [v for v in lookup_package(conn, "pypi", "pillow", "9.0.0") if v.id == "CVE-2023-4863"]
    conn.close()
    assert (match.is_kev, match.kev_date_added, match.kev_due_date) == (True, "2023-09-13", "2023-10-04")


@cache
def _demo_report() -> dict[str, Any]:
    from agent_bom.demo_estate.bootstrap import _run_demo_scan_report

    return _run_demo_scan_report(tenant_id="default")


def _cve_rows() -> list[dict[str, Any]]:
    return [row for row in _demo_report()["findings"] if row.get("finding_type") == "CVE"]


def test_demo_scan_node_fetch_row_fixes_on_the_2x_line():
    (row,) = [r for r in _cve_rows() if r["title"] == "CVE-2022-0235: node-fetch@2.6.1" and r["asset"]["asset_type"] == "mcp_server"]
    assert row["fixed_version"] == "2.6.7"


def test_every_kev_occurrence_carries_the_catalog_dates():
    kev = [row for row in _cve_rows() if row.get("is_kev")]
    assert kev
    assert Counter((row.get("kev_due_date") or "")[:10] for row in kev) == Counter({"2023-10-04": len(kev)})
    assert {row["evidence"].get("kev_date_added") for row in kev} == {"2023-09-13"}


def test_every_occurrence_of_a_cve_carries_its_epss():
    by_cve: dict[str, set[Any]] = {}
    for row in _cve_rows():
        by_cve.setdefault(row["cve_id"], set()).add(row.get("epss_score"))
    assert {cve: scores for cve, scores in by_cve.items() if None in scores or len(scores) != 1} == {}


# NVD: CVE-2024-6387 affects OpenSSH 8.5p1 through 9.7p1 (fixed 9.8p1), CVSS 8.1;
# CVE-2023-38408 affects OpenSSH before 9.3p2, CVSS 9.8. Neither is KEV-listed.
_HOST_FACTS = {"CVE-2024-6387": ("9.8p1", 8.1, "high"), "CVE-2023-38408": ("9.3p2", 9.8, "critical")}


def test_host_cves_read_like_every_other_vulnerability_row():
    rows = [row for row in _cve_rows() if row["cve_id"] in _HOST_FACTS]
    assert sorted(row["cve_id"] for row in rows) == sorted(_HOST_FACTS)
    for row in rows:
        fixed, cvss, severity = _HOST_FACTS[row["cve_id"]]
        installed = row["evidence"]["package_version"]
        assert row["title"] == f"{row['cve_id']}: openssh@{installed}"
        assert (row["fixed_version"], row["cvss_score"], row["severity"]) == (fixed, cvss, severity)
        assert row["evidence"]["package_name"] == "openssh"
        assert isinstance(row["epss_score"], float)
        assert row["is_kev"] is False
        assert row["reachability"] in {"confirmed", "likely", "unknown", "unlikely"}


def test_rehydrated_cve_row_keeps_its_advisory_facts():
    from agent_bom.domain.finding_rehydrate import finding_from_dict

    finding = finding_from_dict(
        {
            "finding_type": "CVE",
            "cve_id": "CVE-2024-6387",
            "cvss_score": 8.1,
            "epss_score": 0.41,
            "is_kev": False,
            "fixed_version": "9.8p1",
            "reachability": "unknown",
            "cwe_ids": ["CWE-362"],
        }
    )
    assert finding is not None
    assert (finding.cvss_score, finding.epss_score, finding.fixed_version, finding.reachability, finding.cwe_ids) == (
        8.1,
        0.41,
        "9.8p1",
        "unknown",
        ["CWE-362"],
    )


def test_estate_cve_rows_carry_the_package_lineage_the_graph_records():
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate

    tags = {asset.asset_id: asset.tags for asset in build_demo_estate(tenant_id="default").assets if asset.resource_type == "package"}
    rows = [row for row in _cve_rows() if row["asset"].get("identifier") in tags]
    assert rows
    transitive = 0
    for row in rows:
        lineage = tags[row["asset"]["identifier"]]
        is_direct = lineage["is_direct"] == "true"
        depth = int(lineage["dependency_depth"])
        assert (row["is_direct"], row["dependency_depth"], row["introduced_via"]) == (is_direct, depth, lineage.get("parent_package"))
        assert (row["evidence"]["package_is_direct"], row["evidence"]["package_dependency_depth"]) == (is_direct, depth)
        transitive += not is_direct
    assert transitive


def test_demo_inventory_rows_expose_lineage_fields():
    rows = [row for row in _cve_rows() if row["asset"]["asset_type"] == "mcp_server"]
    assert rows
    for row in rows:
        assert row["is_direct"] == row["evidence"]["package_is_direct"]
        assert row["dependency_depth"] == row["evidence"]["package_dependency_depth"]
        assert row["introduced_via"] == row["evidence"]["package_parent"]


def test_every_kev_occurrence_is_risk_scored():
    kev = [row for row in _cve_rows() if row.get("is_kev")]
    assert kev and all(isinstance(row["risk_score"], float) and row["risk_score"] > 0 for row in kev)


def test_estate_cve_rows_are_risk_scored():
    assert [row["id"] for row in _cve_rows() if row.get("risk_score") is None] == []


def test_unassessed_findings_carry_no_risk_score_rather_than_zero():
    rows = _demo_report()["findings"]
    assert not [row["id"] for row in rows if row.get("risk_score") == 0 and not row.get("suppressed")]
    assert any(row.get("risk_score") is None for row in rows)


def test_unassessed_risk_round_trips_as_none():
    from agent_bom.domain.finding_rehydrate import finding_from_dict
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType

    finding = Finding(
        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
        source=FindingSource.CLOUD_SECURITY,
        asset=Asset(name="a", asset_type="cloud_resource"),
        severity="high",
        title="t",
    )
    payload = finding.to_dict()
    assert payload["risk_score"] is None
    restored = finding_from_dict(payload)
    assert restored is not None and restored.risk_score is None


def test_sarif_never_reports_an_unassessed_finding_as_score_zero():
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.output.sarif import _unified_finding_properties

    finding = Finding(
        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
        source=FindingSource.CLOUD_SECURITY,
        asset=Asset(name="a", asset_type="cloud_resource"),
        severity="high",
        title="t",
    )
    properties = _unified_finding_properties(finding, "rule", {})
    assert "risk_score" not in properties
    assert properties["risk_score_status"] == "not_assessed"
    finding.risk_score = 7.5
    assert _unified_finding_properties(finding, "rule", {})["risk_score"] == 7.5


def test_slack_renders_unassessed_risk_without_crashing():
    import json

    from agent_bom.integrations.slack import _build_slack_blocks, build_summary_message

    rows = [{"vulnerability_id": "CVE-1", "severity": "high", "package": "p", "risk_score": None}]
    assert "Not assessed" in json.dumps(_build_slack_blocks(rows[0]))
    assert "risk not assessed" in json.dumps(build_summary_message(rows))


def test_public_finding_payload_keeps_the_dependency_lineage():
    from agent_bom.finding_scope import safe_finding_response_payload

    row = {
        "id": "f",
        "severity": "high",
        "evidence": {"package_is_direct": False, "package_dependency_depth": 2, "package_parent": "requests"},
    }
    payload = safe_finding_response_payload(row)
    assert (payload["is_direct"], payload["dependency_depth"], payload["introduced_via"]) == (False, 2, "requests")
    assert "is_direct" not in safe_finding_response_payload({"id": "g", "severity": "high", "evidence": {}})


def test_mcp_scan_summary_carries_lineage_and_kev_deadline():
    from agent_bom.mcp_tools.scan_response import _compact_finding

    row = _compact_finding(
        {
            "id": "f",
            "risk_score": None,
            "kev_due_date": "2023-10-04",
            "is_direct": False,
            "dependency_depth": 2,
            "introduced_via": "requests",
        }
    )
    assert (row["risk_score"], row["kev_due_date"], row["is_direct"], row["dependency_depth"], row["introduced_via"]) == (
        None,
        "2023-10-04",
        False,
        2,
        "requests",
    )


@pytest.mark.parametrize(("version", "fixed"), [("2.6.1", "2.6.7"), ("3.1.0", "3.1.1"), ("3.2.0", None)])
def test_demo_advisory_window_picks_the_installed_release_line(version, fixed):
    from agent_bom.demo_advisories import demo_advisory_window

    row = demo_advisory_window("CVE-2022-0235", "node-fetch", version, "npm")
    assert (row.fixed if row else None) == fixed
