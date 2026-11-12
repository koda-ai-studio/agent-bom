"""Unit tests for the pure parts of the local live-qualification lanes (cgroup, replicas, serving)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

QUALIFICATION = Path(__file__).resolve().parents[1] / "scripts" / "qualification"
sys.path.insert(0, str(QUALIFICATION))

import cgroup_limits  # noqa: E402
import common  # noqa: E402
import kind_replicas  # noqa: E402
import replicas  # noqa: E402
import serving  # noqa: E402

CGROUP_DUMP = """harness_exit=0
memory_max=2147483648
cpu_max=200000/100000
memory_peak=2147483648
memory_events_max=8794
memory_events_oom=0
memory_events_oom_kill=0
cpu_stat_usage_usec=1669109958
cpu_stat_nr_throttled=36
cpu_stat_throttled_usec=3182608
"""


def _evidence(failures: list[str] | None = None) -> dict:
    return {"failures": failures or [], "profiles": []}


def test_cgroup_dump_parses_and_clean_run_passes() -> None:
    result = common.LaneResult("cgroup", "t")
    cgroup_limits.evaluate(result, "p", _evidence(), cgroup_limits.parse_keyvalues(CGROUP_DUMP), oom_killed=False)
    assert result.passed
    measured = result.measurements["p"]
    assert measured["memory_max_mib"] == 2048.0
    assert measured["memory_max_events"] == 8794
    assert measured["cpu_throttled_periods"] == 36
    assert measured["cpu_seconds"] == 1669.1


@pytest.mark.parametrize(
    ("dump", "oom_killed", "evidence", "failed"),
    [
        (CGROUP_DUMP.replace("oom_kill=0", "oom_kill=1"), False, _evidence(), "p_no_oom_kill"),
        (CGROUP_DUMP, True, _evidence(), "p_no_oom_kill"),
        (CGROUP_DUMP.replace("memory_max=2147483648", "memory_max=max"), False, _evidence(), "p_memory_limit_enforced"),
        (CGROUP_DUMP.replace("cpu_max=200000/100000", "cpu_max=max/100000"), False, _evidence(), "p_cpu_limit_enforced"),
        (CGROUP_DUMP.replace("harness_exit=0", "harness_exit=1"), False, _evidence(), "p_harness_exit_zero"),
        (CGROUP_DUMP, False, _evidence(["small/cold: child exited -9"]), "p_workflow_accurate"),
        (CGROUP_DUMP, False, None, "p_workflow_accurate"),
    ],
)
def test_cgroup_lane_fails_on_oom_unenforced_limits_or_inaccuracy(dump, oom_killed, evidence, failed) -> None:
    result = common.LaneResult("cgroup", "t")
    cgroup_limits.evaluate(result, "p", evidence, cgroup_limits.parse_keyvalues(dump), oom_killed=oom_killed)
    assert not result.passed
    assert [check["name"] for check in result.checks if not check["ok"]] == [failed]


def test_memory_summary_reports_anon_and_page_cache_peaks_separately() -> None:
    mib = 1024 * 1024
    samples = f"1 {1000 * mib} {900 * mib} {100 * mib}\n2 {2048 * mib} {1300 * mib} {748 * mib}\nnoise\n"
    assert cgroup_limits.memory_summary(samples) == {
        "samples": 2,
        "peak_current_mib": 2048.0,
        "peak_anon_mib": 1300.0,
        "peak_file_mib": 748.0,
    }
    assert cgroup_limits.memory_summary("") == {"samples": 0}


def test_sampler_records_the_kernel_counters_the_lane_reads() -> None:
    for counter in ("memory.max", "cpu.max", "memory.peak", "memory.events", "cpu.stat", "memory.stat"):
        assert f"/sys/fs/cgroup/{counter}" in cgroup_limits.SAMPLER


def test_replica_helpers_need_two_replicas_to_call_views_consistent() -> None:
    assert replicas.spread({"a": 3, "b": 0, "c": 1}) == 2
    assert replicas.same_everywhere({"a": {"jobs": [1]}, "b": {"jobs": [1]}})
    assert not replicas.same_everywhere({"a": {"jobs": [1]}, "b": {"jobs": [2]}})
    assert not replicas.same_everywhere({"a": {"jobs": [1]}})


def test_kind_values_run_the_documented_postgres_profile_with_replicas() -> None:
    values = kind_replicas.chart_values("agent-bom", "local", 3)
    api = values["controlPlane"]["api"]
    assert api["replicas"] == 3 and api["service"]["type"] == "NodePort"
    assert values["controlPlane"]["postgresSecrets"]["enabled"] is True
    assert {"name": "AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "value": "1"} in api["env"]
    rule = values["controlPlane"]["networkPolicy"]["additionalIngress"][0]
    assert rule["ports"] == [{"port": 8422, "protocol": "TCP"}]


def test_kind_secrets_are_distinct_and_carry_trusted_proxy_attestation() -> None:
    passwords = {"admin": "a" * 32, "app": "b" * 32, "maintenance": "c" * 32}
    documents = {doc["metadata"]["name"]: doc["stringData"] for doc in kind_replicas.secret_documents("ns", passwords, "k" * 48)}
    assert "agent_bom_app:" + "b" * 32 in documents["agent-bom-control-plane-db"]["AGENT_BOM_POSTGRES_URL"]
    assert "agent_bom_maintenance:" + "c" * 32 in documents["agent-bom-control-plane-maintenance"]["AGENT_BOM_POSTGRES_MAINTENANCE_URL"]
    auth = documents["agent-bom-control-plane-auth"]
    assert auth["AGENT_BOM_TRUST_PROXY_AUTH"] == "1" and auth["AGENT_BOM_TRUST_PROXY_AUTH_ISSUER"]
    assert len(auth["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"]) >= 32
    assert (
        len({auth["AGENT_BOM_AUDIT_HMAC_KEY"], auth["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"], auth["AGENT_BOM_BROWSER_SESSION_SIGNING_KEY"]})
        == 3
    )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_kind_values_render_with_the_chart(tmp_path: Path) -> None:
    values = tmp_path / "values.json"
    values.write_text(json.dumps(kind_replicas.chart_values("agent-bom", "local", 3)))
    rendered = subprocess.run(
        ["helm", "template", "agent-bom", str(kind_replicas.CHART), "-n", "agent-bom", "-f", str(values)], capture_output=True, text=True
    )
    assert rendered.returncode == 0, rendered.stderr
    assert "type: NodePort" in rendered.stdout
    assert "replicas: 3" in rendered.stdout
    assert "agent-bom-postgres-verify" not in rendered.stdout


def _outcome(**overrides) -> dict:
    outcome = {
        "exit_code": 0,
        "outcome": "complete",
        "statuses": ["success"],
        "request_identity": ["bearer"],
        "runtime": ["vllm 0.33.0 confirmed"],
        "models": ["facebook/opt-125m"],
        "findings": [],
        "warnings": [],
    }
    outcome.update(overrides)
    return outcome


@pytest.mark.parametrize(
    "overrides",
    [
        {"exit_code": 1},
        {"outcome": "partial"},
        {"findings": ["No authentication observed in MCP server configuration"]},
        {"runtime": ["vllm 0.33.0 declared"]},
        {"request_identity": ["anonymous"]},
        {"statuses": ["partial"]},
    ],
)
def test_serving_success_requires_exit_zero_complete_confirmed_and_no_findings(overrides) -> None:
    good = common.LaneResult("serving", "t")
    serving.expect_success(good, "ok", _outcome(), "bearer")
    assert good.passed
    bad = common.LaneResult("serving", "t")
    serving.expect_success(bad, "bad", _outcome(**overrides), "bearer")
    assert not bad.passed


def test_serving_denied_requires_exit_one_no_models_and_a_denied_warning() -> None:
    warning = "vllm discovery incomplete: endpoint <url> denied (HTTP 401); no inventory was substituted."
    denied = common.LaneResult("serving", "t")
    serving.expect_denied(denied, "d", _outcome(exit_code=1, models=[], statuses=[], warnings=[warning]))
    assert denied.passed
    leaked = common.LaneResult("serving", "t")
    serving.expect_denied(leaked, "d", _outcome(exit_code=1, warnings=[warning]))
    assert not leaked.passed


def test_serving_images_come_from_the_runtime_vendors() -> None:
    assert serving.IMAGES == {
        "llamacpp": "ghcr.io/ggml-org/llama.cpp:server",
        "vllm": "vllm/vllm-openai-cpu:latest",
        "ollama": "ollama/ollama:latest",
    }
    assert serving.GGUF_URL.startswith("https://huggingface.co/Qwen/")
