"""Queue scheduling preserves complete proof while distributing expensive suites."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_unit_tests_run_in_parallel_with_ui_validation_and_are_required():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    unit = jobs["ui-unit"]
    assert unit["needs"] == "changes"
    assert unit["if"] == jobs["ui"]["if"]
    assert unit["strategy"]["matrix"]["shard"] == [1, 2]
    assert "--shard=${{ matrix.shard }}/2" in "\n".join(s.get("run", "") for s in unit["steps"])
    assert "ui-unit" in jobs["test"]["needs"]
    gate = jobs["test"]["steps"][0]
    assert gate["env"]["UI_UNIT_RESULT"] == "${{ needs.ui-unit.result }}"
    assert "UI_UNIT" in gate["run"]


def test_postgres_durations_are_real_nonempty_module_measurements():
    data = json.loads((ROOT / "tests/.ci-postgres-durations.json").read_text())["files"]
    assert len(data) >= 100
    assert sum(data.values()) > 100
    assert all((ROOT / path).is_file() and seconds >= 0 for path, seconds in data.items())


def test_short_deployment_and_docs_checks_share_lint_runner():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    assert not {"compose-contract", "helm-profiles", "docs-strict"} & jobs.keys()
    steps = {s.get("name"): s for s in jobs["lint"]["steps"]}
    for name in [
        "Validate every shipped compose file and overlay combination",
        "Render shipped Helm profiles",
        "Build site (strict, no deploy)",
    ]:
        assert name in steps
        assert "if" in steps[name]
        assert not steps[name].get("continue-on-error")


def test_measured_expensive_graph_modules_do_not_pile_up_on_one_shard():
    from scripts.pytest_ci_plan import DURATIONS_FILE, discover_test_files, load_durations, plan_shards

    # Worker-seconds from merge_group run 44926518668, shard 5. This is a
    # historical replay of the imbalance, not a claim about future wall time.
    observed = {
        "tests/test_mcp_graph_agent_parity.py": 540.57,
        "tests/test_estate_v2_scale.py": 111.54,
        "tests/test_demo_graph_finding_node_parity.py": 68.56,
        "tests/test_current_estate_alias_reads.py": 53.60,
        "tests/api/test_api_proxy_scorecard.py": 22.19,
        "tests/test_graph_relationship_contract.py": 19.83,
        "tests/test_inventory_query_work.py": 10.23,
        "tests/test_ocsf_boundary.py": 9.51,
        "tests/api/test_current_graph_estate.py": 9.06,
        "tests/test_graph_qualification.py": 8.77,
        "tests/api/test_scan_detail_perf_budget.py": 8.40,
        "tests/test_image_identity_and_partial_scan.py": 7.14,
    }
    files = discover_test_files(ROOT / "tests")
    shards = plan_shards(files, total=16, durations=load_durations(DURATIONS_FILE))
    assigned = [path for shard in shards for path in shard]
    assert len(assigned) == len(set(assigned)) == len(files)
    assert set(assigned) == set(files)
    loads = [sum(observed.get(path.relative_to(ROOT).as_posix(), 0) for path in shard) for shard in shards]
    # Leave at least 219 worker-seconds of the old 869-second cluster on
    # other runners, while retaining every test module exactly once.
    assert max(loads) <= 650, loads
