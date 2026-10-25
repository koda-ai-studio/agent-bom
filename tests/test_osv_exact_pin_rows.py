"""OSV enumerated-version pin rows match by equality and are never ambiguous."""

from __future__ import annotations

from agent_bom.core.versions.osv import version_match_state
from agent_bom.db.lookup import _select_vulnerability_rows


def _pin(vuln_id: str, pinned: str) -> dict:
    return {
        "id": vuln_id,
        "introduced": pinned,
        "fixed": "",
        "last_affected": pinned,
        "ecosystem": "pypi",
        "limit_version": "",
    }


def test_non_ecosystem_pin_never_reports_unknown():
    assert version_match_state("4.2.0", "v0.1.1d", "", "v0.1.1d", "pypi", "") == "unaffected"


def test_non_ecosystem_pin_matches_identical_string():
    assert version_match_state("v0.1.1d", "v0.1.1d", "", "v0.1.1d", "pypi", "") == "affected"


def test_valid_pin_matches_equal_version_only():
    assert version_match_state("1.0.0", "1.0", "", "1.0", "pypi", "") == "affected"
    assert version_match_state("1.0.1", "1.0", "", "1.0", "pypi", "") == "unaffected"


def test_git_tag_pins_do_not_select_unverified_findings():
    rows = [_pin("CVE-2023-26302", "v0.1.1d"), _pin("CVE-2023-26303", "0.1.1-pre")]
    assert _select_vulnerability_rows(rows, "4.2.0") == []
