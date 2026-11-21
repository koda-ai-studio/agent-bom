"""Fixture-only tests for the real-repository accuracy measurement (no network)."""

from __future__ import annotations

from pathlib import Path

from scripts.measure_real_repo_accuracy import scan_summary, unverified_summary
from scripts.real_repo_accuracy_compare import (
    AdvisoryContext,
    build_alias_groups,
    compare_advisories,
    compare_packages,
    finding_ids,
    package_key,
)
from scripts.real_repo_accuracy_lockfiles import parse_lockfile

GO_MOD = """module example.com/app

go 1.24

require (
\tgithub.com/a/b v1.2.3
\tgolang.org/x/net v0.20.0 // indirect
)

require github.com/c/d v0.1.0

replace github.com/c/d => github.com/e/f v0.2.0

replace example.com/local => ../local
"""

PNPM_LOCK = """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.3.0

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}

  left-pad@1.3.0:
    resolution: {integrity: sha512-y}

  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-z}

  local-thing@file:packages/thing:
    resolution: {directory: packages/thing, type: directory}
"""

CARGO_LOCK = """version = 4

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-crate"
version = "0.1.0"

[[package]]
name = "forked"
version = "0.3.0"
source = "git+https://github.com/x/forked?rev=abc#abc"
"""

UV_LOCK = """version = 1

[[package]]
name = "Requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "temporalio"
version = "1.0.0"
source = { editable = "." }
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_go_mod_applies_replace_and_keeps_indirect(tmp_path: Path) -> None:
    parsed = parse_lockfile(_write(tmp_path, "go.mod", GO_MOD), "go.mod")
    assert parsed.packages == {
        ("Go", "github.com/a/b", "v1.2.3"),
        ("Go", "golang.org/x/net", "v0.20.0"),
        ("Go", "github.com/e/f", "v0.2.0"),
    }
    assert parsed.skipped == []


def test_pnpm_lock_strips_peer_suffix_and_skips_local(tmp_path: Path) -> None:
    parsed = parse_lockfile(_write(tmp_path, "pnpm-lock.yaml", PNPM_LOCK), "pnpm-lock.yaml")
    assert parsed.packages == {
        ("npm", "@babel/core", "7.24.0"),
        ("npm", "left-pad", "1.3.0"),
        ("npm", "react-dom", "18.2.0"),
    }
    assert parsed.skipped == ["local-thing@file:packages/thing"]


def test_cargo_lock_keeps_registry_crates_only(tmp_path: Path) -> None:
    parsed = parse_lockfile(_write(tmp_path, "Cargo.lock", CARGO_LOCK), "Cargo.lock")
    assert parsed.packages == {("crates.io", "serde", "1.0.200")}
    assert sorted(parsed.skipped) == ["forked@0.3.0 (git)", "my-crate@0.1.0 (workspace)"]


def test_uv_lock_normalizes_names_and_skips_editable(tmp_path: Path) -> None:
    parsed = parse_lockfile(_write(tmp_path, "uv.lock", UV_LOCK), "uv.lock")
    assert parsed.packages == {("PyPI", "requests", "2.31.0")}
    assert parsed.skipped == ["temporalio@1.0.0 (editable)"]


def test_package_key_normalizes_per_ecosystem() -> None:
    assert package_key("PyPI", "Zope.Interface", "5.0") == ("PyPI", "zope-interface", "5.0")
    assert package_key("Go", "github.com/a/b", "v1.2.3") == ("Go", "github.com/a/b", "1.2.3")
    assert package_key("npm", "@Scope/Pkg", "1.0.0") == ("npm", "@scope/pkg", "1.0.0")


def test_alias_groups_join_ghsa_cve_pysec_transitively() -> None:
    records = {
        "GHSA-aaaa": {"id": "GHSA-aaaa", "aliases": ["CVE-2024-1"]},
        "PYSEC-2024-9": {"id": "PYSEC-2024-9", "aliases": ["CVE-2024-1"]},
        "GO-2024-5": {"id": "GO-2024-5", "aliases": ["GHSA-bbbb"]},
    }
    groups = build_alias_groups(records)
    assert groups["GHSA-AAAA"] == groups["PYSEC-2024-9"] == groups["CVE-2024-1"]
    assert groups["GO-2024-5"] == groups["GHSA-BBBB"]
    assert groups["GO-2024-5"] != groups["GHSA-AAAA"]


def test_finding_ids_reads_every_identifier_field() -> None:
    finding = {
        "vulnerability_id": "GHSA-aaaa",
        "cve_id": "GHSA-aaaa",
        "advisory_ids": ["GHSA-aaaa", "PYSEC-2024-9"],
        "advisory_aliases": ["CVE-2024-1"],
        "cve_ids": [],
    }
    assert finding_ids(finding) == {"GHSA-AAAA", "PYSEC-2024-9", "CVE-2024-1"}


def _context(records: dict, found_packages: set, synced: str = "2026-11-20T00:00:00Z") -> AdvisoryContext:
    return AdvisoryContext(records=records, found_packages=found_packages, db_synced_at=synced)


def test_compare_counts_alias_match_once_and_classifies_differences() -> None:
    pkg = ("PyPI", "requests", "2.31.0")
    gone = ("PyPI", "absent", "1.0")
    records = {
        "GHSA-AAAA": {"id": "GHSA-aaaa", "aliases": ["CVE-2024-1"], "modified": "2026-01-01T00:00:00Z"},
        "PYSEC-2024-9": {"id": "PYSEC-2024-9", "aliases": ["CVE-2024-1"], "modified": "2026-01-01T00:00:00Z"},
        "GHSA-WWWW": {"id": "GHSA-wwww", "withdrawn": "2026-02-01T00:00:00Z", "modified": "2026-02-01T00:00:00Z"},
        "GHSA-NEWW": {"id": "GHSA-neww", "published": "2026-11-20T05:00:00Z", "modified": "2026-11-20T05:00:00Z"},
        "GHSA-MISS": {"id": "GHSA-miss", "modified": "2026-01-01T00:00:00Z"},
        "GHSA-GONE": {"id": "GHSA-gone", "modified": "2026-01-01T00:00:00Z"},
        "GHSA-XTRA": {"id": "GHSA-xtra", "modified": "2026-01-01T00:00:00Z"},
    }
    expected = {
        pkg: {"GHSA-AAAA", "PYSEC-2024-9", "GHSA-WWWW", "GHSA-NEWW", "GHSA-MISS"},
        gone: {"GHSA-GONE"},
    }
    found = {
        pkg: [{"CVE-2024-1"}, {"GHSA-AAAA", "PYSEC-2024-9"}, {"GHSA-XTRA"}, {"NVD-ONLY-1"}],
    }
    result = compare_advisories(expected, found, _context(records, {pkg}))

    assert result.matched == 1
    assert result.expected == 5
    reasons = {(m["package"], m["reason"]) for m in result.missed}
    assert reasons == {
        ("absent@1.0", "package_not_found"),
        ("requests@2.31.0", "withdrawn"),
        ("requests@2.31.0", "published_after_db_sync"),
        ("requests@2.31.0", "unexplained"),
    }
    extra = {(e["ids"][0], e["reason"]) for e in result.extra}
    assert extra == {("GHSA-XTRA", "osv_does_not_list_version"), ("NVD-ONLY-1", "not_in_osv")}
    assert result.unexplained_missed == 1
    assert result.false_positive_candidates == 1


def test_compare_packages_reports_both_directions() -> None:
    expected = {("npm", "a", "1.0.0"), ("npm", "b", "2.0.0")}
    found = {("npm", "a", "1.0.0"), ("npm", "c", "3.0.0")}
    result = compare_packages(expected, found)
    assert result == {
        "expected": 2,
        "found": 1,
        "missing": ["npm:b@2.0.0"],
        "unexpected": ["npm:c@3.0.0"],
    }


def test_unverified_summary_counts_findings_and_possibly_affected_separately() -> None:
    report = {
        "packages": [{"purl": "pkg:pypi/pytest@8.4.2"}, {"purl": "pkg:npm/x@1.0.0"}],
        "findings": [
            {
                "finding_category": "vulnerability",
                "asset": {"asset_type": "package", "identifier": "pkg:pypi/pytest@8.4.2"},
                "vulnerability_id": "GHSA-1",
            }
        ],
        "possibly_affected": [
            {"id": "CVE-2025-71176", "package": {"purl": "pkg:pypi/pytest@8.4.2"}},
            {"id": "CVE-2025-71176", "package": {"purl": "pkg:pypi/pytest@8.4.2"}},
            {"id": "CVE-9", "package": {"purl": "pkg:npm/x@1.0.0"}},
        ],
    }
    entry = {"ecosystem": "PyPI", "manifests": ["setup.cfg"], "reason": "ranges"}
    summary = unverified_summary(entry, report)
    assert summary["packages_found"] == 1
    assert summary["advisories_reported"] == 1
    assert summary["possibly_affected_reported"] == 1


def test_scan_summary_strips_local_checkout_paths() -> None:
    repo_dir = Path("/tmp/work/repos/owner__repo-abc")
    report = {
        "_exit_code": 1,
        "scan_run": {
            "outcome": "partial",
            "issues": [{"code": "scan_note", "affects_coverage": True, "message": f"maven:{repo_dir}/a/pom.xml: BOM"}],
        },
        "coverage_warnings": [{"kind": "k", "detail": f"see {repo_dir}/b", "package_count": 2}],
    }
    summary = scan_summary(report, repo_dir)
    assert summary["issues"][0]["message"] == "maven:<repo>/a/pom.xml: BOM"
    assert summary["coverage_warnings"][0]["detail"] == "see <repo>/b"
    assert "/tmp/work" not in str(summary)
