"""``intel_lookup`` answers a CVE from KEV, EPSS and the Node.js core index when OSV has no record."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_bom.db.schema import init_db
from agent_bom.intel_lookup import lookup_advisory
from agent_bom.scanners import nodejs_advisory_data

_SYNCED = "2026-11-12T00:00:00+00:00"


def _synced_db(tmp_path: Path, *, nodejs: bool = True) -> Path:
    db = tmp_path / "vulns.db"
    conn = init_db(db)
    for source, count in (("osv", 10), ("kev", 1), ("epss", 1), ("nodejs", 204 if nodejs else 0)):
        conn.execute("INSERT INTO sync_meta (source, last_synced, record_count) VALUES (?, ?, ?)", (source, _SYNCED, count))
    conn.execute(
        "INSERT INTO kev_entries (cve_id, date_added, due_date, product, vendor_project) VALUES (?, ?, ?, ?, ?)",
        ("CVE-2021-44228", "2021-12-10", "2021-12-24", "Log4j2", "Apache"),
    )
    conn.execute(
        "INSERT INTO epss_scores (cve_id, probability, percentile, updated_at) VALUES (?, ?, ?, ?)",
        ("CVE-2021-44228", 0.99979, 99.99, _SYNCED),
    )
    conn.commit()
    conn.close()
    if nodejs:
        shutil.copy(nodejs_advisory_data.bundled_snapshot_path(), tmp_path / nodejs_advisory_data.SNAPSHOT_FILENAME)
    return db


def test_kev_and_epss_cve_without_osv_record_is_found_as_partial(tmp_path):
    result = lookup_advisory("cve-2021-44228", db_path=_synced_db(tmp_path))
    assert result["found"] is True
    advisory = result["advisory"]
    assert advisory["id"] == "CVE-2021-44228"
    assert advisory["record_completeness"] == "partial"
    assert advisory["is_kev"] is True
    assert advisory["kev_date_added"] == "2021-12-10"
    assert advisory["epss_probability"] == 0.99979
    assert advisory["affected"] == []
    assert advisory["severity"] is None
    by_source = {item["source"]: item for item in advisory["record_sources"]}
    assert set(by_source) == {"kev", "epss"}
    assert by_source["kev"]["vendor_project"] == "Apache"
    assert by_source["kev"]["product"] == "Log4j2"
    assert "osv" in advisory["not_found_in"]
    json.dumps(result)


def test_nodejs_core_cve_is_found_from_the_synced_index(tmp_path):
    result = lookup_advisory("CVE-2024-27980", db_path=_synced_db(tmp_path))
    assert result["found"] is True
    advisory = result["advisory"]
    assert advisory["record_completeness"] == "partial"
    assert advisory["severity"] == "high"
    assert "child_process.spawn" in advisory["summary"]
    assert advisory["affected"] == [
        {
            "ecosystem": "nodejs-core",
            "package_name": "node",
            "introduced": None,
            "fixed": None,
            "last_affected": None,
            "vulnerable": "18.x || 20.x || 21.x",
            "patched": "^18.20.2 || ^20.12.2 || ^21.7.3",
        }
    ]
    sources = [item["source"] for item in advisory["record_sources"]]
    assert sources == ["nodejs"]
    assert advisory["is_kev"] is False


def test_true_miss_names_every_source_searched(tmp_path):
    result = lookup_advisory("CVE-1999-99999", db_path=_synced_db(tmp_path))
    assert result["found"] is False
    database = result["database"]
    assert database["searched"] == ["osv", "kev", "epss", "nodejs"]
    assert database["note"] == "No record of CVE-1999-99999 in OSV, KEV, EPSS or Node.js security WG."


def test_partial_record_validates_against_the_api_response_model(tmp_path):
    from agent_bom.api.read_models.governance_b import IntelAdvisoryResponse

    db = _synced_db(tmp_path)
    for cve in ("CVE-2021-44228", "CVE-2024-27980"):
        model = IntelAdvisoryResponse.model_validate(lookup_advisory(cve, db_path=db))
        assert model.advisory is not None
        assert model.advisory.source_policy.source_id in {"cisa_kev", "nodejs_security_wg"}


def test_unsynced_nodejs_index_is_not_claimed_as_searched(tmp_path):
    result = lookup_advisory("CVE-2024-27980", db_path=_synced_db(tmp_path, nodejs=False))
    assert result["found"] is False
    assert "nodejs" not in result["database"]["searched"]
