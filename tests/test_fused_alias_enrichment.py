"""EPSS/KEV joins never cross a stale fused alias group.

Uses the lodash fused fixture: every row of the CVE-2021-23337 / GHSA-35jh /
CVE-2026-4800 / GHSA-r5fr group lists the other three as aliases. CVE-2026-4800
carries a high EPSS and a KEV entry; CVE-2021-23337 a low EPSS and no KEV.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.db.lookup import lookup_package
from tests.test_fused_local_aliases import _build_fused_db

EPSS = {"CVE-2021-23337": (0.01, 0.40), "CVE-2026-4800": (0.90, 0.99), "CVE-2020-28500": (0.05, 0.70)}
KEV = {"CVE-2026-4800": ("2026-10-01", "2026-10-22")}


def _db(tmp_path: Path) -> Path:
    path = _build_fused_db(tmp_path / "vulns.db")
    conn = sqlite3.connect(path)
    for cve, (probability, percentile) in EPSS.items():
        conn.execute(
            "INSERT INTO epss_scores(cve_id,probability,percentile,updated_at) VALUES (?,?,?,'2026-10-01')", (cve, probability, percentile)
        )
    for cve, (added, due) in KEV.items():
        conn.execute("INSERT INTO kev_entries(cve_id,date_added,due_date) VALUES (?,?,?)", (cve, added, due))
    conn.commit()
    conn.close()
    return path


def _rows(tmp_path: Path) -> dict[str, object]:
    conn = sqlite3.connect(_db(tmp_path))
    conn.row_factory = sqlite3.Row
    try:
        return {vuln.id: vuln for vuln in lookup_package(conn, "npm", "lodash", "4.17.20")}
    finally:
        conn.close()


def test_own_cve_row_takes_only_its_own_epss_and_kev(tmp_path):
    rows = _rows(tmp_path)

    assert rows["CVE-2021-23337"].epss_probability == 0.01
    assert rows["CVE-2021-23337"].is_kev is False
    assert rows["CVE-2026-4800"].epss_probability == 0.90
    assert rows["CVE-2026-4800"].is_kev is True


def test_fused_alias_row_without_own_cve_takes_no_borrowed_enrichment(tmp_path):
    rows = _rows(tmp_path)

    # GHSA-35jh's stored aliases name both CVEs; neither may lend it EPSS/KEV.
    assert rows["GHSA-35jh-r3h4-6jhm"].epss_probability is None
    assert rows["GHSA-35jh-r3h4-6jhm"].is_kev is False


def test_single_cve_alias_still_joins(tmp_path):
    rows = _rows(tmp_path)

    assert rows["GHSA-29mw-wpgm-hmr9"].epss_probability == 0.05


def test_cli_findings_keep_their_own_enrichment(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", _db(tmp_path))
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)

    result = CliRunner().invoke(
        main, ["check", "lodash@4.17.20", "--ecosystem", "npm", "--format", "json", "--offline", "--allow-stale-db"]
    )
    findings = {detail["id"]: detail for detail in json.loads(result.output)["vulnerability_details"]}

    assert findings["CVE-2021-23337"]["epss_score"] == 0.01
    assert findings["CVE-2021-23337"]["is_kev"] is False
    assert findings["CVE-2026-4800"]["epss_score"] == 0.90
    assert findings["CVE-2026-4800"]["is_kev"] is True
