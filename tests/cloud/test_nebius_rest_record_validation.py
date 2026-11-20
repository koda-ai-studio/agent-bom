"""Nebius REST records: typed fields, per-record isolation, official instance shape."""

import httpx
import pytest

from agent_bom.cloud import nebius


def serve(monkeypatch, key, records):
    response = httpx.Response(200, json={key: records}, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)


# ── Container services ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        {"id": {"x": 1}, "name": "n", "image": "a:1"},
        {"id": "2", "name": ["n"], "image": "a:1"},
        {"id": "2", "name": "n", "image": {"i": 1}},
        {"name": None, "image": None},
        "junk",
    ],
)
def test_malformed_container_service_is_isolated(monkeypatch, bad):
    serve(monkeypatch, "containers", [{"id": "1", "name": "good1", "image": "a:1"}, bad, {"id": "3", "name": "good3", "image": "b:1"}])
    agents, warnings = nebius._discover_container_services("k", "p")
    assert [a.name for a in agents] == ["nebius-container:good1", "nebius-container:good3"]
    assert [a.mcp_servers[0].args for a in agents] == [["run", "a:1"], ["run", "b:1"]]
    assert len(warnings) == 1 and warnings[0].startswith("nebius:containers:unavailable:")
    assert "{" not in warnings[0]


def test_container_service_without_name_uses_id_and_null_name_is_malformed(monkeypatch):
    serve(monkeypatch, "containers", [{"id": "c1", "name": None}, {"id": "c2"}, {"id": "c3"}])
    agents, warnings = nebius._discover_container_services("k", "p")
    assert [a.name for a in agents] == ["nebius-container:c2", "nebius-container:c3"]
    assert len({a.config_path for a in agents}) == 2
    assert len(warnings) == 1


def test_container_service_without_image_is_not_a_docker_target(monkeypatch):
    serve(monkeypatch, "containers", [{"id": "c1", "name": "svc"}])
    agents, _ = nebius._discover_container_services("k", "p")
    assert agents[0].mcp_servers[0].command in (None, "")


# ── AI Studio ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [{"id": None, "name": "m"}, {"id": "m", "version": {"a": 1}}, {"id": ["m"]}, {"id": "m", "status": {"s": 1}}, {}],
)
def test_malformed_model_is_isolated(monkeypatch, bad):
    serve(monkeypatch, "models", [{"id": "good1"}, bad, {"id": "good2", "version": 3}])
    agents, warnings = nebius._discover_ai_studio("k", "p")
    assert [a.name for a in agents] == ["nebius-ai-studio:good1", "nebius-ai-studio:good2"]
    assert [a.mcp_servers[0].packages[0].version for a in agents] == ["latest", "3"]
    assert all("None" not in a.config_path for a in agents)
    assert len(warnings) == 1 and warnings[0].startswith("nebius:ai-studio:unavailable:")


def test_openai_compatible_model_list_shape(monkeypatch):
    serve(monkeypatch, "data", [{"id": "meta-llama/Llama-3.3-70B-Instruct", "object": "model", "owned_by": "system"}])
    agents, warnings = nebius._discover_ai_studio("k", "p")
    assert [a.name for a in agents] == ["nebius-ai-studio:meta-llama/Llama-3.3-70B-Instruct"]
    assert warnings == []


# ── Compute instances (nebius/api compute/v1 Instance) ──────────────────


def official(name, preset="8gpu-128vcpu-1600gb", platform="gpu-h100-sxm", state="RUNNING"):
    return {
        "metadata": {"id": f"computeinstance-{name}", "name": name, "parent_id": "project-x", "resource_version": "4"},
        "spec": {"resources": {"platform": platform, "preset": preset}, "boot_disk": {"attach_mode": "READ_WRITE"}},
        "status": {"state": state},
    }


def test_official_instance_shape_is_supported(monkeypatch):
    serve(monkeypatch, "items", [official("train-1"), official("cpu-box", preset="4vcpu-16gb", platform="cpu-d3")])
    agents, warnings = nebius._discover_gpu_instances("k", "p")
    assert warnings == []
    assert [a.name for a in agents] == ["nebius-gpu:train-1"]
    agent = agents[0]
    assert agent.metadata["gpu_count"] == 8
    assert agent.metadata["gpu_type"] == "gpu-h100-sxm"
    assert agent.version == "RUNNING"
    assert agent.config_path == "nebius://p/compute/computeinstance-train-1"
    assert agent.metadata["cloud_origin"]["resource_id"] == "computeinstance-train-1"


def test_gpu_platform_without_preset_count_is_still_gpu(monkeypatch):
    record = official("x")
    del record["spec"]["resources"]["preset"]
    serve(monkeypatch, "items", [record])
    agents, _ = nebius._discover_gpu_instances("k", "p")
    assert [a.metadata["gpu_type"] for a in agents] == ["gpu-h100-sxm"]


def test_legacy_numeric_strings_are_coerced(monkeypatch):
    serve(monkeypatch, "instances", [{"id": "i1", "name": "s", "resources": {"gpus": "8"}, "platform_id": "x"}])
    agents, warnings = nebius._discover_gpu_instances("k", "p")
    assert warnings == []
    assert agents[0].metadata["gpu_count"] == 8


@pytest.mark.parametrize("bad", [{"unexpected": True}, {"metadata": {"labels": {}}}, {"resources": {"gpus": None}, "id": "i"}])
def test_unrecognised_instance_record_warns(monkeypatch, bad):
    serve(monkeypatch, "items", [official("a"), bad])
    agents, warnings = nebius._discover_gpu_instances("k", "p")
    assert [a.name for a in agents] == ["nebius-gpu:a"]
    assert len(warnings) == 1 and warnings[0].startswith("nebius:instances:unavailable:")
