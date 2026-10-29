"""A pre-release is a real fix when no stable release has shipped yet.

twisted 26.4.0 shape: OSV carries ``fixed: 26.10.0rc1`` for several high
advisories and no stable fix. Dropping it reports "no fix available", which
over-claims; surfacing it unflagged under-claims the upgrade risk. Mocked
advisory payloads only — no network.
"""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.finding import _remediation_guidance_for_vulnerability
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.output.json_sections import _vulnerability_json
from agent_bom.scanners import build_vulnerabilities, parse_fixed_version
from agent_bom.scanners.advisory_merge import merge_advisory_clusters
from agent_bom.scanners.local_advisories import _local_vuln_to_vulnerability
from agent_bom.scanners.osv import _next_unaffected_fixes
from agent_bom.scanners.package_check_result import serialize_vulnerability

PRERELEASE_REMEDIATION = "Upgrade twisted to 26.10.0rc1 (pre-release; no stable fix published yet)."


def _twisted_advisory(vuln_id: str = "CVE-2026-115775", fixed: str = "26.10.0rc1") -> dict:
    return {
        "id": vuln_id,
        "summary": "Twisted web request smuggling",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
        "affected": [
            {
                "package": {"name": "twisted", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


def _twisted() -> Package:
    return Package(name="twisted", version="26.4.0", ecosystem="pypi")


def test_parse_fixed_version_returns_prerelease_only_fix() -> None:
    assert parse_fixed_version(_twisted_advisory(), "twisted", "pypi", current_version="26.4.0") == "26.10.0rc1"


def test_parse_fixed_version_still_prefers_stable_over_prerelease() -> None:
    advisory = _twisted_advisory()
    advisory["affected"][0]["ranges"].append({"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "26.10.0"}]})
    assert parse_fixed_version(advisory, "twisted", "pypi", current_version="26.4.0") == "26.10.0"


def test_next_window_fix_prefers_stable_over_earlier_prerelease() -> None:
    windows = [
        ("0", None, "1.0", []),
        ("2.0", "2.1rc1", None, []),
        ("3.0", "3.1", None, []),
    ]
    assert _next_unaffected_fixes(windows, "0.9", "pypi") == ["3.1"]
    assert _next_unaffected_fixes([windows[0], windows[1]], "0.9", "pypi") == ["2.1rc1"]


def test_build_vulnerabilities_surfaces_and_flags_prerelease_fix() -> None:
    vulns = build_vulnerabilities([_twisted_advisory()], _twisted())
    assert len(vulns) == 1
    assert vulns[0].fixed_version == "26.10.0rc1"
    assert vulns[0].fix_is_prerelease is True
    assert vulns[0].severity == Severity.HIGH


def test_build_vulnerabilities_stable_fix_is_not_flagged() -> None:
    vulns = build_vulnerabilities([_twisted_advisory(fixed="26.10.0")], _twisted())
    assert vulns[0].fixed_version == "26.10.0"
    assert vulns[0].fix_is_prerelease is False


def _local_vuln(**overrides: object) -> SimpleNamespace:
    """Shape of a local advisory DB row as ``_local_vuln_to_vulnerability`` reads it."""
    row: dict[str, object] = {
        "id": "CVE-2026-115776",
        "summary": "Twisted header injection",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": None,
        "fixed_version": "26.10.0rc1",
        "ecosystem": "PyPI",
        "source": "osv",
        "aliases": [],
        "epss_probability": None,
        "epss_percentile": None,
        "is_kev": False,
        "kev_date_added": None,
    }
    row.update(overrides)
    return SimpleNamespace(**row)


def test_local_db_prerelease_fix_is_flagged() -> None:
    vuln = _local_vuln_to_vulnerability(_local_vuln())
    assert vuln.fixed_version == "26.10.0rc1"
    assert vuln.fix_is_prerelease is True
    assert _local_vuln_to_vulnerability(_local_vuln(fixed_version="26.10.0")).fix_is_prerelease is False


def test_distro_letter_suffix_fix_is_not_flagged_as_prerelease() -> None:
    lv = _local_vuln(id="DLA-4403-1", summary="tzdata", severity="LOW", cvss_score=None, fixed_version="2025b-0+deb11u2")
    lv.ecosystem = "Debian:11"
    vuln = _local_vuln_to_vulnerability(lv)
    assert vuln.fixed_version == "2025b-0+deb11u2"
    assert vuln.fix_is_prerelease is False


def test_merge_fix_fallback_carries_prerelease_flag() -> None:
    bare = Vulnerability(id="CVE-2026-115778", summary="s", severity=Severity.HIGH, cvss_score=7.5, advisory_sources=["osv"])
    sibling = Vulnerability(
        id="PYSEC-2026-1",
        summary="s",
        severity=Severity.HIGH,
        cvss_score=7.5,
        fixed_version="26.10.0rc1",
        fix_is_prerelease=True,
        aliases=["CVE-2026-115778"],
        advisory_sources=["osv"],
    )
    merged = merge_advisory_clusters([bare, sibling], fix_fallback=True)
    assert len(merged) == 1
    assert merged[0].fixed_version == "26.10.0rc1"
    assert merged[0].fix_is_prerelease is True


def test_remediation_text_names_prerelease_fix() -> None:
    vuln = build_vulnerabilities([_twisted_advisory()], _twisted())[0]
    assert _remediation_guidance_for_vulnerability(vuln, _twisted()) == PRERELEASE_REMEDIATION


def test_remediation_text_for_stable_fix_is_unchanged() -> None:
    vuln = build_vulnerabilities([_twisted_advisory(fixed="26.10.0")], _twisted())[0]
    assert _remediation_guidance_for_vulnerability(vuln, _twisted()) == "Upgrade twisted to 26.10.0."


def test_vulnerability_json_and_check_payload_carry_flag() -> None:
    vuln = build_vulnerabilities([_twisted_advisory()], _twisted())[0]
    assert _vulnerability_json(vuln)["fix_is_prerelease"] is True
    serialized = serialize_vulnerability(vuln)
    assert serialized["fixed_version"] == "26.10.0rc1"
    assert serialized["fix_is_prerelease"] is True
    stable = build_vulnerabilities([_twisted_advisory(fixed="26.10.0")], _twisted())[0]
    assert serialize_vulnerability(stable)["fix_is_prerelease"] is False
