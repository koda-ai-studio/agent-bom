"""Repeated scan input flags are additive, never last-one-wins."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

_BASE = ["scan", "--offline", "--no-scan", "--no-discover", "--exit-zero", "-f", "json", "-q"]


def _scan(tmp_path: Path, *args: str) -> dict:
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, [*_BASE, *args, "-o", str(out)], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text())


def _package_names(report: dict) -> set[str]:
    return {pkg["name"] for agent in report["agents"] for server in agent.get("mcp_servers", []) for pkg in server.get("packages", [])}


def _cdx(path: Path, name: str, version: str) -> Path:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"component": {"type": "application", "name": path.stem, "version": "1.0.0"}},
                "compositions": [{"aggregate": "complete"}],
                "components": [{"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}"}],
            }
        )
    )
    return path


def _inventory(path: Path, agent: str, package: str) -> Path:
    path.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "name": agent,
                        "agent_type": "custom",
                        "mcp_servers": [
                            {
                                "name": f"{agent}-srv",
                                "command": "python",
                                "packages": [{"name": package, "version": "1.0.0", "ecosystem": "pypi"}],
                            }
                        ],
                    }
                ]
            }
        )
    )
    return path


def _project(path: Path, package: str) -> Path:
    path.mkdir()
    (path / "requirements.txt").write_text(f"{package}==1.0.0\n")
    return path


def test_repeated_project_scans_every_project(tmp_path):
    a = _project(tmp_path / "proj-a", "alpha-pkg")
    b = _project(tmp_path / "proj-b", "beta-pkg")
    report = _scan(tmp_path, "-p", str(a), "-p", str(b))
    assert {"alpha-pkg", "beta-pkg"} <= _package_names(report)
    assert {"project:proj-a", "project:proj-b"} <= {agent["name"] for agent in report["agents"]}
    notices = [notice for notice in report["scan_run"]["issues"] if notice["code"] == "multi_project_primary_scope"]
    assert len(notices) == 1 and str(a) in notices[0]["message"]


def test_single_project_unchanged(tmp_path):
    a = _project(tmp_path / "proj-a", "alpha-pkg")
    report = _scan(tmp_path, "-p", str(a))
    assert "alpha-pkg" in _package_names(report)


def test_repeated_sbom_ingests_every_sbom(tmp_path):
    a = _cdx(tmp_path / "a.cdx.json", "alpha-pkg", "1.0.0")
    b = _cdx(tmp_path / "b.cdx.json", "beta-pkg", "2.0.0")
    report = _scan(tmp_path, "--sbom", str(a), "--sbom", str(b))
    assert {"alpha-pkg", "beta-pkg"} <= _package_names(report)


def test_repeated_sbom_names_pair_positionally(tmp_path):
    a = _cdx(tmp_path / "a.cdx.json", "alpha-pkg", "1.0.0")
    b = _cdx(tmp_path / "b.cdx.json", "beta-pkg", "2.0.0")
    report = _scan(tmp_path, "--sbom", str(a), "--sbom-name", "svc-a", "--sbom", str(b), "--sbom-name", "svc-b")
    names = json.dumps(report["agents"])
    assert "svc-a" in names and "svc-b" in names


def test_sbom_name_count_must_match_sbom_count(tmp_path):
    a = _cdx(tmp_path / "a.cdx.json", "alpha-pkg", "1.0.0")
    b = _cdx(tmp_path / "b.cdx.json", "beta-pkg", "2.0.0")
    result = CliRunner().invoke(main, [*_BASE, "--sbom", str(a), "--sbom", str(b), "--sbom-name", "only-one"])
    assert result.exit_code == 2
    assert "--sbom-name" in result.output


def test_repeated_inventory_loads_every_inventory(tmp_path):
    a = _inventory(tmp_path / "a.json", "agent-a", "alpha-pkg")
    b = _inventory(tmp_path / "b.json", "agent-b", "beta-pkg")
    report = _scan(tmp_path, "--inventory", str(a), "--inventory", str(b))
    assert {"agent-a", "agent-b"} <= {agent["name"] for agent in report["agents"]}
    assert {"alpha-pkg", "beta-pkg"} <= _package_names(report)


def test_repeated_external_scan_ingests_every_report(tmp_path):
    a = _cdx(tmp_path / "ext-a.cdx.json", "alpha-pkg", "1.0.0")
    b = _cdx(tmp_path / "ext-b.cdx.json", "beta-pkg", "2.0.0")
    report = _scan(tmp_path, "--external-scan", str(a), "--external-scan", str(b))
    assert {"alpha-pkg", "beta-pkg"} <= _package_names(report)


def test_repeated_config_dir_discovers_every_directory(tmp_path, monkeypatch):
    seen: list[str | None] = []

    def _fake_discover(project_dir=None, **_kwargs):
        seen.append(project_dir)
        return []

    monkeypatch.setattr("agent_bom.cli.agents.discover_all", _fake_discover)
    a = tmp_path / "cfg-a"
    b = tmp_path / "cfg-b"
    a.mkdir()
    b.mkdir()
    CliRunner().invoke(main, [*_BASE, "--config-dir", str(a), "--config-dir", str(b)])
    assert str(a) in seen and str(b) in seen


@pytest.mark.parametrize(
    "flag",
    ["--repo", "--correlate", "--vex", "--policy", "--baseline", "--ignore-file"],
)
def test_single_valued_inputs_reject_repeats(tmp_path, flag):
    one = tmp_path / "one.json"
    two = tmp_path / "two.json"
    one.write_text("{}")
    two.write_text("{}")
    first, second = ("https://example.invalid/a", "https://example.invalid/b") if flag == "--repo" else (str(one), str(two))
    result = CliRunner().invoke(main, [*_BASE, flag, first, flag, second])
    assert result.exit_code == 2
    assert "accepts only one value" in result.output


def test_push_target_scope_covers_every_repeated_input(tmp_path):
    from types import SimpleNamespace

    from agent_bom.evidence.push_scope import cli_target_scope

    a = _project(tmp_path / "proj-a", "alpha-pkg")
    b = _project(tmp_path / "proj-b", "beta-pkg")
    single = cli_target_scope(SimpleNamespace(project=str(a)))
    assert cli_target_scope(SimpleNamespace(project=str(a), extra_projects=())) == single
    assert cli_target_scope(SimpleNamespace(project=str(a), extra_projects=(str(b),))) != single


def test_repeated_project_expands_surfaces_for_every_project(tmp_path):
    a = _project(tmp_path / "proj-a", "alpha-pkg")
    b = _project(tmp_path / "proj-b", "beta-pkg")
    (a / "main.tf").write_text('resource "aws_s3_bucket" "a" { bucket = "a" }\n')
    (b / "main.tf").write_text('resource "aws_s3_bucket" "b" { bucket = "b" }\n')
    report = _scan(tmp_path, "-p", str(a), "-p", str(b))
    messages = " ".join(finding["message"] for finding in report["iac_findings"]["findings"])
    assert "bucket 'a'" in messages and "bucket 'b'" in messages, messages


def test_same_relative_iac_path_in_two_roots_keeps_distinct_findings(tmp_path):
    a = _project(tmp_path / "proj-a", "alpha-pkg")
    b = _project(tmp_path / "proj-b", "beta-pkg")
    for root, bucket in ((a, "a"), (b, "b")):
        (root / "main.tf").write_text(f'resource "aws_s3_bucket" "{bucket}" {{ bucket = "{bucket}" }}\n')
    for args in (("-p", str(a), "-p", str(b)), ("--iac", str(a), "--iac", str(b))):
        report = _scan(tmp_path, *args)
        paths = {finding["file_path"] for finding in report["iac_findings"]["findings"]}
        assert paths == {"proj-a/main.tf", "proj-b/main.tf"}
        ids = [finding["id"] for finding in report["findings"]]
        assert len(ids) == len(set(ids)) == report["iac_findings"]["total"]
