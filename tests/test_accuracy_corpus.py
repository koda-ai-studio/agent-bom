"""Offline accuracy regression corpus: exact inventory and verdict sets frozen from ground truth.

Each case under ``tests/fixtures/accuracy_corpus/<case>/`` holds a minimal excerpt
of a real upstream project and an ``expected.json`` frozen from ground truth
(the upstream files themselves, npm registry selections and OSV API advisories
captured on 2026-11-02). Every assertion is exact set equality, so a missed
package (false negative) and an invented one (false positive) both fail.

Dependency manifests are committed with a ``.fixture`` suffix so the
repository's own dependency scan never inventories them; ``_materialize``
restores the real names in a temporary copy, and turns ``dot-<name>``
directories (user-level client configs such as ``home/dot-cursor``, which the
repository ignores as ``.cursor/``) into ``.<name>``. The corpus runs with outbound
sockets blocked: registry and advisory answers come from the recorded data.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
from pathlib import Path

import pytest

from agent_bom.parsers import scan_project_directory
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings
from agent_bom.secret_scanner import scan_secrets

CORPUS = Path(__file__).parent / "fixtures" / "accuracy_corpus"
FIXTURE_SUFFIX = ".fixture"
DOT_PREFIX = "dot-"


def _expected(case: str) -> dict:
    return json.loads((CORPUS / case / "expected.json").read_text())


def _materialize(case: str, tmp_path: Path) -> Path:
    root = tmp_path / case
    shutil.copytree(CORPUS / case, root, ignore=shutil.ignore_patterns("expected.json"))
    for path in sorted(root.rglob(f"*{FIXTURE_SUFFIX}")):
        path.rename(path.with_name(path.name[: -len(FIXTURE_SUFFIX)]))
    for path in sorted(root.rglob(f"{DOT_PREFIX}*"), reverse=True):
        path.rename(path.with_name("." + path.name[len(DOT_PREFIX) :]))
    return root


def _coordinates(packages) -> set[str]:
    return {f"{pkg.name}@{pkg.version}" for pkg in packages}


@pytest.fixture(autouse=True)
def offline_corpus(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("accuracy corpus must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    # Go checksum-database verification is an online integrity check, not inventory.
    monkeypatch.setattr("agent_bom.parsers.compiled_parsers.verify_go_checksums", lambda go_sum, modules: {})
    for env in ("AGENT_BOM_SCAN_FIXTURE_MANIFESTS", "AGENT_BOM_INCLUDE_RANGE_RESOLVED"):
        monkeypatch.delenv(env, raising=False)
    reset_scan_warnings()
    yield
    reset_scan_warnings()


@pytest.mark.parametrize("case", ["pnpm_v5_vite_4_0_0", "pnpm_v6_vite_5_0_0", "pnpm_v9_vite_6_0_0", "go_node_exporter_1_3_0"])
def test_lockfile_inventory_is_exact(case, tmp_path):
    root = _materialize(case, tmp_path)
    dir_map = scan_project_directory(root)
    assert set(dir_map) == {root.resolve()}
    assert _coordinates(dir_map[root.resolve()]) == set(_expected(case)["packages"])
    assert [w for w in peek_coverage_warnings() if w.get("kind") != "scope_exclusion"] == []


def test_go_mod_only_lines_are_not_inventory(tmp_path):
    expected = _expected("go_node_exporter_1_3_0")
    root = _materialize("go_node_exporter_1_3_0", tmp_path)
    names = {pkg.name for pkg in scan_project_directory(root)[root.resolve()]}
    assert expected["go_mod_only_modules"]
    assert names.isdisjoint(expected["go_mod_only_modules"])


def test_poetry_test_fixtures_are_skipped_and_locked_packages_kept(tmp_path):
    case = "poetry_1_2_0_test_fixtures"
    expected = _expected(case)
    root = _materialize(case, tmp_path)
    warnings: list[str] = []
    dir_map = scan_project_directory(root, warnings=warnings)
    assert set(dir_map) == {root.resolve()}
    assert _coordinates(dir_map[root.resolve()]) == set(expected["packages"])
    receipts = [w for w in peek_coverage_warnings() if w.get("reason") == "fixture_manifest"]
    assert len(receipts) == 1 and receipts[0]["kind"] == "scope_exclusion"
    assert receipts[0]["excluded_count"] == len(expected["skipped_fixture_directories"])
    assert all(rel in warnings[0] for rel in expected["skipped_fixture_directories"])


def _patch_recorded_registry_and_osv(monkeypatch, case_dir: Path) -> None:
    from agent_bom import scanners, transitive
    from agent_bom.scanners import package_scan
    from agent_bom.scanners.scan_options import _package_db_key

    registry = json.loads((case_dir / "registry_selected.json").read_text())
    osv = json.loads((case_dir / "osv_records.json").read_text())

    async def recorded_range(name, spec, client):
        assert registry[name]["declared"] == spec
        return registry[name]["selected"]

    async def recorded_osv(packages):
        return {_package_db_key(pkg): osv.get(f"{pkg.name}@{pkg.version}", []) for pkg in packages}

    async def no_supplemental(*args, **kwargs):
        return 0

    monkeypatch.setattr(transitive, "resolve_npm_range_version", recorded_range)
    monkeypatch.setattr(scanners, "query_osv_batch", recorded_osv)
    monkeypatch.setattr(scanners, "_db_covered_ecosystems", lambda ecosystems: set())
    monkeypatch.setattr(package_scan, "_scan_local_advisories", lambda scannable, options, keys: (0, set(), []))
    monkeypatch.setattr(package_scan, "_scan_supplemental_advisories", no_supplemental)


def _scan_template(monkeypatch, tmp_path):
    from agent_bom.models import Agent, AgentType, MCPServer
    from agent_bom.scanners import package_scan
    from agent_bom.scanners.scan_options import ScanOptions

    case = "vite_template_range_resolved"
    _patch_recorded_registry_and_osv(monkeypatch, CORPUS / case)
    root = _materialize(case, tmp_path)
    dir_map = scan_project_directory(root)
    packages = [pkg for pkgs in dir_map.values() for pkg in pkgs]
    agent = Agent(
        name="project:template",
        agent_type=AgentType.CUSTOM,
        config_path=str(root),
        mcp_servers=[MCPServer(name="template-vue", command="", packages=packages)],
    )
    blast_radii = asyncio.run(package_scan.scan_agents([agent], show_scan_banner=False, options=ScanOptions()))
    return agent, packages, blast_radii


def _exit_code(agent, blast_radii) -> int:
    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(agents=[agent], blast_radii=blast_radii)
    ctx = ScanContext(con=Console(quiet=True), agents=[agent], blast_radii=blast_radii, report=report)
    return compute_exit_code(
        ctx,
        fail_on_severity="low",
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=True,
    )


def test_template_ranges_are_possibly_affected_not_findings(monkeypatch, tmp_path):
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json

    expected = _expected("vite_template_range_resolved")
    agent, packages, blast_radii = _scan_template(monkeypatch, tmp_path)

    assert _coordinates(packages) == set(expected["packages"])
    assert all(pkg.resolved_from_registry and pkg.floating_reference and pkg.version_confidence == "low" for pkg in packages)
    candidates = {f"{pkg.name}@{pkg.version}": pkg.possibly_affected for pkg in packages if pkg.possibly_affected}
    assert set(candidates) == set(expected["possibly_affected"])
    for coordinate, entries in candidates.items():
        recorded = set(expected["possibly_affected"][coordinate])
        matched = {next(iter(recorded & ({e["id"], *e["aliases"]})), None) for e in entries}
        assert matched == recorded and len(entries) == len(recorded)
        assert {(e["reason"], e["match_confidence_tier"], e["verdict"]) for e in entries} == {
            ("registry_selected_version", "unverified_range", "possibly_affected")
        }
    assert all(pkg.vulnerabilities == [] for pkg in packages)
    assert blast_radii == []

    summary = json.loads(json.dumps(to_json(AIBOMReport(agents=[agent], blast_radii=blast_radii)), default=str))["summary"]
    assert summary["total_vulnerabilities"] == 0
    assert not any(summary.get(key) for key in ("critical_findings", "high_findings", "medium_findings", "low_findings"))
    # The severity gate stays clear, but unresolved applicability is partial evidence.
    assert _exit_code(agent, blast_radii) == 1


def test_template_ranges_trip_the_gate_only_when_opted_in(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_INCLUDE_RANGE_RESOLVED", "1")
    agent, packages, blast_radii = _scan_template(monkeypatch, tmp_path)
    assert blast_radii and all(not pkg.possibly_affected for pkg in packages)
    assert _exit_code(agent, blast_radii) == 1


def _discover_under_home(monkeypatch, case: str, tmp_path: Path, agent_type):
    import agent_bom.discovery as discovery

    home = _materialize(case, tmp_path) / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(discovery, "get_platform", lambda: "Darwin")
    return home, discovery.discover_global_configs([agent_type], quiet=True)


def test_windsurf_user_config_is_discovered(monkeypatch, tmp_path):
    from agent_bom.models import AgentType

    expected = _expected("windsurf_user_config")
    home, agents = _discover_under_home(monkeypatch, "windsurf_user_config", tmp_path, AgentType.WINDSURF)
    config = (home.parent / expected["config_path"]).resolve()
    servers = {(server.name, Path(server.config_path or "").resolve()) for agent in agents for server in agent.mcp_servers}
    assert servers == {(name, config) for name in expected["servers"]}


def test_cursor_remote_auth_header_counts_as_authentication(monkeypatch, tmp_path):
    from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
    from agent_bom.models import AgentType

    expected = _expected("cursor_remote_auth_header")
    _, agents = _discover_under_home(monkeypatch, "cursor_remote_auth_header", tmp_path, AgentType.CURSOR)
    assert {server.name for agent in agents for server in agent.mcp_servers} == set(expected["servers"])
    flagged = {
        finding.evidence.get("server_name") or finding.asset.name
        for finding in evaluate_mcp_auth_posture(agents)
        if finding.evidence.get("mcp_auth_weakness") == "unauthenticated_server"
    }
    assert flagged == set(expected["unauthenticated_servers"])


def test_typosquat_verdicts_are_exact():
    from agent_bom.malicious import check_typosquat

    expected = _expected("typosquat_names")
    assert {row["name"]: check_typosquat(row["name"], row["ecosystem"]) for row in expected["legitimate"]} == {
        row["name"]: None for row in expected["legitimate"]
    }
    assert {row["name"]: check_typosquat(row["name"], row["ecosystem"]) for row in expected["typosquats"]} == {
        row["name"]: row["target"] for row in expected["typosquats"]
    }


def test_go_reference_count_has_a_different_evidence_scope(tmp_path):
    root = _materialize("go_node_exporter_1_3_0", tmp_path)
    lines = (root / "go-list-reference.txt").read_text().splitlines()
    assert lines[0] == "github.com/prometheus/node_exporter"
    assert len(lines) == 121
    reference = {line.split()[0] for line in lines[1:]}
    inventory = {pkg.name for pkg in scan_project_directory(root)[root.resolve()]}
    assert len(reference) == 120
    assert len(inventory) == 57
    assert len(reference - inventory) == 63


def test_secret_rules_report_literals_and_not_references_labels_or_locators(tmp_path):
    root = _materialize("secret_assignments", tmp_path)
    found = sorted((finding.file_path, finding.line_number, finding.secret_type) for finding in scan_secrets(root).findings)
    expected = sorted((row["file"], row["line"], row["type"]) for row in _expected("secret_assignments")["findings"])
    assert found == expected
