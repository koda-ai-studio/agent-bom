"""Correctness of the end-to-end workflow resource harness (no timing assertions)."""

from __future__ import annotations

import json

import httpx
import pytest

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_profiles import (
    ESTATE_SOURCE,
    PROFILES,
    MockUpstream,
    expected_findings,
    inventory_from_estate,
)


def test_profiles_pin_source_sizes_concurrency_and_limits() -> None:
    assert {"ci-budget", "small-self-hosted", "multi-replica-local"} <= set(PROFILES)
    for name, profile in PROFILES.items():
        assert profile.name == name
        assert profile.agents > 0 and profile.seed == 2145
        assert 0 < profile.vulnerable_package_rate < 1
        assert profile.store in {"sqlite", "postgres"}
        assert profile.api_replicas >= 1 and profile.concurrent_pushes >= 1
        assert profile.cpu_limit > 0 and profile.memory_limit_mib > 0
        assert profile.query_repeats >= 5
    multi = PROFILES["multi-replica-local"]
    assert multi.store == "postgres" and multi.api_replicas >= 2 and multi.concurrent_pushes >= 2
    assert ESTATE_SOURCE == "scripts/generate_graph_benchmark_estate.py"


def test_inventory_from_estate_passes_the_shipped_inventory_schema(tmp_path) -> None:
    from agent_bom.inventory import build_agents_from_inventory, load_inventory

    report, _summary = generate_estate(agents=6, seed=2145, vulnerable_package_rate=0.3)
    inventory = inventory_from_estate(report)
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    agents = build_agents_from_inventory(load_inventory(str(path)), str(path))

    assert [agent.name for agent in agents] == [agent["name"] for agent in report["agents"]]
    scannable = [
        package
        for agent in report["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
        if package["ecosystem"] != "oci"
    ]
    assert sum(len(server.packages) for agent in agents for server in agent.mcp_servers) == len(scannable)


def test_expected_findings_cover_only_scannable_vulnerable_package_versions() -> None:
    report, _summary = generate_estate(agents=10, seed=2145, vulnerable_package_rate=0.3)
    inventory = inventory_from_estate(report)
    expected = expected_findings(report, inventory)
    present = {
        (package["name"], package["version"])
        for agent in inventory["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
    }
    assert expected, "fixture must produce findings to check accuracy against"
    assert {(name, version) for _vuln, name, version in expected} <= present


def _batch(upstream: MockUpstream, queries: list[dict]) -> httpx.Response:
    return upstream(httpx.Request("POST", "https://api.osv.dev/v1/querybatch", json={"queries": queries}))


def test_mock_upstream_answers_osv_counts_bytes_and_injects_retryable_failures() -> None:
    upstream = MockUpstream(vulnerable={("left-pad", "1.0.0"): "CVE-2026-000001"}, fail_first_batches=1)
    query = [
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.0"},
        {"package": {"name": "x", "ecosystem": "npm"}, "version": "2.0.0"},
    ]

    assert _batch(upstream, query).status_code == 503
    answer = _batch(upstream, query)
    assert answer.status_code == 200
    vulns = [row.get("vulns", []) for row in answer.json()["results"]]
    assert [len(row) for row in vulns] == [1, 0]
    detail = upstream(httpx.Request("GET", f"https://api.osv.dev/v1/vulns/{vulns[0][0]['id']}"))
    assert detail.status_code == 200
    assert detail.json()["affected"][0]["package"]["name"] == "left-pad"
    assert upstream(httpx.Request("GET", "https://registry.npmjs.org/left-pad/latest")).status_code == 404
    go = MockUpstream(vulnerable={("example.com/mod", "1.2.0"): "CVE-2026-000002"})
    go_answer = _batch(go, [{"package": {"name": "example.com/mod", "ecosystem": "Go"}, "version": "v1.2.0"}])
    assert go_answer.json()["results"][0]["vulns"][0]["id"] == "CVE-2026-000002"

    counts = upstream.snapshot()
    assert counts["requests"] == 4
    assert counts["by_host"] == {"api.osv.dev": 3, "registry.npmjs.org": 1}
    assert counts["injected_failures"] == 1
    assert counts["request_bytes"] > 0 and counts["response_bytes"] > 0


def test_percentile_is_an_observed_nearest_rank() -> None:
    from scripts.perf.workflow_budget import percentile

    assert percentile([], 95) == 0.0
    assert percentile([3.0], 95) == 3.0
    samples = [float(value) for value in range(1, 21)]
    assert percentile(samples, 50) == 10.0
    assert percentile(samples, 95) == 19.0


def test_network_guard_blocks_non_loopback_and_counts_attempts() -> None:
    import socket

    from scripts.perf.workflow_budget import network_guard

    with network_guard() as guard:
        with pytest.raises(OSError):
            socket.create_connection(("192.0.2.1", 443), timeout=0.5)
        assert guard.blocked == ["192.0.2.1:443"]
    assert socket.socket.connect is not None


def _phase(**accuracy: bool) -> dict:
    base = {"scanned_matches_expected": True, "stored_matches_scanned": True, "rebuilt_matches_stored": True}
    return {"process": {"exit_code": 0}, "result": {"accuracy": {**base, **accuracy}, "network": {"blocked_connections": []}}}


def test_evidence_failures_flag_crashed_phases_inaccurate_findings_and_live_network() -> None:
    from scripts.run_workflow_resource_benchmark import evidence_failures

    restart_ok = {"process": {"exit_code": 0}, "result": {"findings_match_before_restart": True}}
    clean = {"profile": {"name": "p"}, "cold": _phase(), "warm": _phase(), "restart": restart_ok}
    assert evidence_failures({"profiles": [clean]}) == []

    broken = {
        "profile": {"name": "p"},
        "cold": _phase(scanned_matches_expected=False),
        "warm": {"process": {"exit_code": 1}, "result": None},
        "restart": {"process": {"exit_code": 0}, "result": {"findings_match_before_restart": False}},
        "cancel": {"recover": {"process": {"exit_code": 0}, "result": {"findings_match_expected": False}}},
    }
    broken["cold"]["result"]["network"]["blocked_connections"] = ["192.0.2.1:443"]
    assert evidence_failures({"profiles": [broken]}) == [
        "p/cold: scanned_matches_expected is false",
        "p/cold: live network attempted: ['192.0.2.1:443']",
        "p/warm: child exited 1",
        "p/restart: findings changed across restart",
        "p/cancel: retried push did not converge to the expected findings",
    ]

    replicas = {
        "profile": {"name": "m"},
        "replicas": {"processes": [{"exit_code": 0}, {"exit_code": 0}], "results": [_phase()["result"], None]},
    }
    assert evidence_failures({"profiles": [replicas]}) == ["m/replica-1: no result"]


def test_evidence_failures_include_equivalence_failures() -> None:
    from scripts.run_workflow_resource_benchmark import evidence_failures

    phase = _phase()
    phase["result"]["equivalence"] = {"failures": ["update_delete: open_matches_expected"], "known_gaps": ["resolved row lost identity"]}
    entry = {"profile": {"name": "p"}, "cold": phase}
    assert evidence_failures({"profiles": [entry]}) == ["p/cold: equivalence update_delete: open_matches_expected"]


def test_push_body_carries_the_cli_source_and_target_scope(tmp_path) -> None:
    """``scan --push-url`` sends source_id and target_scope; without them a push replaces nothing."""
    from agent_bom.evidence.push_scope import valid_target_scope
    from scripts.perf.workflow_profiles import WORKFLOW_PUSH_SOURCE_ID, cli_push_body

    inventory = tmp_path / "inventory.json"
    report = {"agents": [{"name": "a", "config_path": "/secret/path"}], "blast_radius": [], "idempotency_key": "x"}
    first = json.loads(cli_push_body(json.dumps(report).encode(), inventory))
    second = json.loads(cli_push_body(json.dumps({**report, "blast_radius": [{"id": 1}]}).encode(), inventory))
    other = json.loads(cli_push_body(json.dumps(report).encode(), tmp_path / "other.json"))

    assert first["source_id"] == WORKFLOW_PUSH_SOURCE_ID
    assert valid_target_scope(first["target_scope"])
    assert first["target_scope"] == second["target_scope"] != other["target_scope"]
    assert "idempotency_key" not in first, "the harness chooses the key per push"
    assert "config_path" not in first["agents"][0]


def _nightly_job(name: str) -> dict:
    from pathlib import Path

    import yaml

    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/perf-scale-evidence.yml").read_text())
    return workflow["jobs"][name]


def test_nightly_postgres_workflow_job_migrates_like_postgres_scale_evidence_and_records_plans() -> None:
    sqlite_job = _nightly_job("workflow-resource-budget")
    job = _nightly_job("workflow-resource-budget-postgres")
    assert job["if"] == sqlite_job["if"]
    assert job["services"]["postgres"]["image"].startswith("postgres:16")
    env = job["env"]
    assert env["AGENT_BOM_POSTGRES_URL"].startswith("postgresql://agent_bom_app:")
    assert env["AGENT_BOM_POSTGRES_MAINTENANCE_URL"].startswith("postgresql://agent_bom_maintenance:")
    assert env["AGENT_BOM_AUDIT_HMAC_KEY"]

    steps = {step.get("name"): step for step in job["steps"]}
    migrate = steps["Migrate ephemeral Postgres schema"]["run"]
    for required in ("init.app_password", "init.maintenance_password", "alembic -c deploy/supabase/postgres/alembic.ini upgrade head"):
        assert required in migrate
    assert "--extra postgres" in steps["Install agent-bom (from source)"]["run"]

    measure = steps["Measure the Postgres workflow profiles"]["run"]
    assert "--profile small-self-hosted-postgres" in measure and "--profile multi-replica-local" in measure
    assert '--postgres-url "$AGENT_BOM_POSTGRES_URL"' in measure

    plans = steps["Record hot-read query plans"]["run"]
    assert "scripts/run_graph_postgres_explain.py" in plans and "--run" in plans and "--hot-reads" in plans

    upload = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["if"] == "always()"
    assert "workflow-resource-budget-postgres.json" in upload["with"]["path"]
