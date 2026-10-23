"""Runtime components with an explicit CPE flow through the NVD CPE matcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom import config
from agent_bom.cpe_match import cpe_vendor_hint
from agent_bom.db.schema import init_db
from agent_bom.parsers.image_runtimes import runtime_packages_from_config
from agent_bom.scanners.local_advisories import _scan_packages_db_conn


def _conn():
    conn = init_db(Path(":memory:"))
    conn.executemany(
        "INSERT INTO cpe_matches (cve_id, criteria, vendor, product, version, "
        "version_start, version_start_op, version_end, version_end_op) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            ("CVE-2026-0001", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "php", "php", None, "8.3.0", "including", "8.3.36", "excluding"),
            (
                "CVE-2026-0002",
                "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                "nodejs",
                "node.js",
                None,
                "22.0.0",
                "including",
                "22.30.0",
                "excluding",
            ),
            ("CVE-2026-0003", "cpe:2.3:a:other:php:*:*:*:*:*:*:*:*", "other", "php", None, None, None, None, None),
        ],
    )
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
        conn.execute(
            "INSERT INTO vulns (id, summary, severity, cvss_score, source) VALUES (?, 'runtime flaw', 'critical', 9.8, 'nvd')", (cve,)
        )
    conn.commit()
    return conn


def _runtime(env: str):
    (pkg,) = runtime_packages_from_config({"config": {"Env": [env]}})
    return pkg


def test_vendor_hint_prefers_explicit_cpe() -> None:
    assert cpe_vendor_hint(_runtime("NODE_VERSION=22.23.4")) == "nodejs"


@pytest.mark.parametrize("enabled", [False, True])
def test_runtime_cpe_matches_regardless_of_long_tail_flag(monkeypatch: pytest.MonkeyPatch, enabled: bool) -> None:
    monkeypatch.setattr(config, "ENABLE_CPE_MATCH", enabled)
    php, node = _runtime("PHP_VERSION=8.3.30"), _runtime("NODE_VERSION=22.23.4")
    _scan_packages_db_conn(_conn(), [php, node], set())
    assert [v.id for v in php.vulnerabilities] == ["CVE-2026-0001"]
    assert [v.id for v in node.vulnerabilities] == ["CVE-2026-0002"]
    assert php.vulnerabilities[0].match_confidence_tier == "nvd_cpe_candidate"


def test_fixed_runtime_release_has_no_cpe_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "ENABLE_CPE_MATCH", False)
    php = _runtime("PHP_VERSION=8.3.36")
    _scan_packages_db_conn(_conn(), [php], set())
    assert php.vulnerabilities == []
