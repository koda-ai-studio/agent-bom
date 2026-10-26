"""Ladder rung 3: unlocked declarations resolved transitively from PyPI JSON metadata (mocked)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.parsers.python_parsers import parse_pip_packages
from agent_bom.scanners.state import capture_coverage_warnings
from tests._pypi_fake import FakePyPI

_REQUESTS = {
    "2.31.0": {"requires_dist": ["urllib3<3,>=1.21.1", "idna<4,>=2.5"]},
    "2.32.3": {
        "requires_dist": [
            "charset-normalizer<4,>=2",
            "idna<4,>=2.5",
            "urllib3<3,>=1.21.1",
            "certifi>=2017.4.17",
            "PySocks!=1.5.7,>=1.5.6; extra == 'socks'",
            "chardet<6,>=3.0.2; extra == 'use-chardet-on-py3'",
        ]
    },
    "3.0.0a1": {"requires_dist": []},
}
_INDEX = {
    "requests": _REQUESTS,
    "charset-normalizer": {"3.4.0": {"requires_dist": []}},
    "idna": {"3.7": {"requires_dist": []}, "3.10": {"requires_dist": None}},
    "urllib3": {"2.2.3": {"requires_dist": ["brotli>=1; platform_python_implementation == 'CPython' and extra == 'brotli'"]}},
    "certifi": {"2024.8.30": {"requires_dist": None}},
    "pysocks": {"1.7.1": {"requires_dist": None}},
    "pywin32": {"308": {"requires_dist": None}},
    "tomli": {"2.0.1": {"requires_dist": None}},
}


@pytest.fixture()
def pypi(monkeypatch):
    def install(index=_INDEX, **kwargs):
        fake = FakePyPI(index, **kwargs)
        monkeypatch.setattr("agent_bom.parsers.pypi_resolution.fetch_pypi_json", fake)
        return fake

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    return install


def _scan(directory):
    with capture_coverage_warnings() as warnings:
        pkgs = parse_pip_packages(directory)
    return {p.name: p for p in pkgs}, warnings


def test_declared_ranges_resolve_transitively_to_newest_satisfying_versions(tmp_path, pypi):
    pypi()
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\ndependencies = ["requests>=2.31,<3"]\n')

    pkgs, warnings = _scan(tmp_path)

    assert {name: p.version for name, p in pkgs.items()} == {
        "requests": "2.32.3",
        "charset-normalizer": "3.4.0",
        "idna": "3.10",
        "urllib3": "2.2.3",
        "certifi": "2024.8.30",
    }
    assert pkgs["requests"].is_direct is True and pkgs["requests"].dependency_depth == 0
    assert pkgs["urllib3"].is_direct is False
    assert pkgs["urllib3"].parent_package == "requests" and pkgs["urllib3"].dependency_depth == 1
    assert pkgs["urllib3"].purl == "pkg:pypi/urllib3@2.2.3"
    provenance = package_version_provenance(pkgs["urllib3"])
    assert provenance["version_source"] == "resolved_at_scan"
    assert provenance["pinned"] is False
    assert provenance["resolved_version"] == "2.2.3"
    assert package_version_provenance(pkgs["requests"])["declared_version"] == "<3,>=2.31"
    [note] = warnings
    assert note["kind"] == "scan_note"
    assert "resolved at scan time from declared ranges" in note["detail"]
    assert "add a lockfile for exact results" in note["detail"]
    run = effective_scan_run(SimpleNamespace(coverage_warnings=warnings, agents=[]))
    assert run.outcome is ScanOutcome.COMPLETE
    assert [(i.code, i.affects_coverage) for i in run.issues] == [("scan_note", False)]


def test_extras_and_markers_are_evaluated_for_the_documented_target(tmp_path, pypi):
    pypi()
    (tmp_path / "requirements.txt").write_text(
        "requests[socks]>=2.31\npywin32>=300; sys_platform == 'win32'\ntomli>=2; python_version < '3.11'\n"
    )
    pkgs, _ = _scan(tmp_path)
    assert "pysocks" in pkgs
    assert pkgs["pysocks"].parent_package == "requests"
    assert "chardet" not in pkgs
    assert "brotli" not in pkgs
    # Linux CPython 3.12 target: Windows-only and pre-3.11 requirements do not apply.
    assert pkgs["pywin32"].version == "unknown"
    assert pkgs["tomli"].version == "unknown"


def test_prereleases_yanked_and_python_incompatible_releases_are_skipped(tmp_path, pypi):
    pypi(
        {
            "lib": {
                "1.0": {"requires_dist": []},
                "1.1": {"requires_dist": [], "requires_python": ">=3.13"},
                "1.2": {"requires_dist": [], "yanked": True},
                "2.0b1": {"requires_dist": []},
            }
        }
    )
    (tmp_path / "requirements.txt").write_text("lib>=1\n")
    pkgs, _ = _scan(tmp_path)
    assert pkgs["lib"].version == "1.0"


def test_shared_dependency_satisfies_every_constraint(tmp_path, pypi):
    pypi(
        {
            "a": {"1.0": {"requires_dist": ["c<2"]}},
            "b": {"1.0": {"requires_dist": ["c>=1"]}},
            "c": {"1.5": {"requires_dist": []}, "2.0": {"requires_dist": []}},
        }
    )
    (tmp_path / "requirements.txt").write_text("b>=1\na>=1\n")
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["c"].version == "1.5"
    assert [w["kind"] for w in warnings] == ["scan_note"]


def test_unresolvable_requirement_is_a_named_gap_and_the_rest_still_resolves(tmp_path, pypi):
    pypi(fail={"idna"})
    (tmp_path / "requirements.txt").write_text("requests>=2.31\nnot-on-pypi>=1\n")
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["requests"].version == "2.32.3"
    assert pkgs["not-on-pypi"].version == "unknown"
    gaps = [w for w in warnings if w.get("kind") != "scan_note"]
    [gap] = gaps
    assert "transitive dependencies not resolved" in gap["detail"]
    assert "not-on-pypi" in gap["detail"] and "idna" in gap["detail"]
    run = effective_scan_run(SimpleNamespace(coverage_warnings=warnings, agents=[]))
    assert run.outcome is ScanOutcome.PARTIAL


def test_no_release_satisfying_the_range_is_a_gap(tmp_path, pypi):
    pypi()
    (tmp_path / "requirements.txt").write_text("requests>=9\n")
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["requests"].version == "unknown"
    assert any("requests" in w["detail"] and "no release" in w["detail"] for w in warnings)


def test_sdist_only_release_without_metadata_is_a_gap_not_a_build(tmp_path, pypi):
    pypi({"legacy": {"0.9": {"requires_dist": None, "wheel": False}}})
    (tmp_path / "requirements.txt").write_text("legacy>=0.1\n")
    pkgs, warnings = _scan(tmp_path)
    assert pkgs["legacy"].version == "0.9"
    assert any("legacy" in w["detail"] and "metadata" in w["detail"] for w in warnings)


def test_package_budget_is_bounded_and_reported(tmp_path, pypi, monkeypatch):
    pypi()
    monkeypatch.setattr("agent_bom.parsers.pypi_resolution.DEFAULT_BUDGET.max_packages", 2)
    (tmp_path / "requirements.txt").write_text("requests>=2.31\n")
    pkgs, warnings = _scan(tmp_path)
    assert len([p for p in pkgs.values() if p.version != "unknown"]) <= 2
    assert any("budget" in w["detail"] for w in warnings)


def test_exact_pins_are_resolved_transitively_too(tmp_path, pypi):
    fake = pypi()
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nidna>=3\n")
    pkgs, _ = _scan(tmp_path)
    assert pkgs["requests"].version == "2.31.0"
    assert pkgs["idna"].version == "3.10"
    assert "urllib3" in pkgs
    assert all("/json" in url for url in fake.requests)


def test_thirty_requirement_project_resolves_within_bounds(tmp_path, pypi):
    index = {f"pkg{i}": {"1.0": {"requires_dist": [f"dep{i}>=1", "shared>=1"]}} for i in range(30)}
    index |= {f"dep{i}": {"1.0": {"requires_dist": []}, "1.1": {"requires_dist": []}} for i in range(30)}
    index["shared"] = {"1.0": {"requires_dist": []}}
    fake = pypi(index)
    (tmp_path / "requirements.txt").write_text("".join(f"pkg{i}>=1\n" for i in range(30)))
    pkgs, warnings = _scan(tmp_path)
    assert len(pkgs) == 61
    assert all(p.version != "unknown" for p in pkgs.values())
    assert [w["kind"] for w in warnings] == ["scan_note"]
    assert len(fake.requests) == 61
