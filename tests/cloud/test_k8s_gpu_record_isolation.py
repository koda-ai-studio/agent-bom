"""Per-record and per-container isolation for Kubernetes GPU inventory."""

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave, nebius
from agent_bom.cloud.k8s_gpu_common import iter_gpu_containers, iter_infiniband_pods, parse_quantity


def container(name="model", image="fixture/model:1", limits=None, requests=None):
    resources = {}
    if limits is not None:
        resources["limits"] = limits
    if requests is not None:
        resources["requests"] = requests
    return {"name": name, "image": image, "resources": resources}


def pod(name, *containers, namespace="ns"):
    return {"metadata": {"name": name, "namespace": namespace}, "spec": {"containers": list(containers)}}


GPU = {"nvidia.com/gpu": "1"}
IB = {"rdma/ib": "1", "nvidia.com/gpu": "2"}


@pytest.mark.parametrize("bad", [None, "junk", container(image=7, limits=GPU), {"name": "x", "image": "i:1", "resources": "bad"}])
def test_bad_container_does_not_hide_later_container_in_same_pod(bad):
    errors: list[Exception] = []
    found = list(iter_gpu_containers([pod("multi", bad, container(name="good", limits=GPU))], errors=errors))
    assert [(c.pod, c.container, c.image, c.gpus) for c in found] == [("multi", "good", "fixture/model:1", 1)]
    assert len(errors) == 1


def test_strict_mode_still_raises():
    with pytest.raises((TypeError, ValueError, AttributeError)):
        list(iter_gpu_containers([pod("p", None)]))


def test_unnamed_pods_are_rejected_not_merged():
    unnamed = pod("x", container(limits=GPU))
    del unnamed["metadata"]["name"]
    errors: list[Exception] = []
    assert list(iter_gpu_containers([unnamed, unnamed], errors=errors)) == []
    assert len(errors) == 2


def test_non_gpu_pod_with_odd_metadata_is_not_an_error():
    errors: list[Exception] = []
    assert list(iter_gpu_containers([{"metadata": {}, "spec": {"containers": [container()]}}], errors=errors)) == []
    assert errors == []


@pytest.mark.parametrize("value,expected", [("1", 1), (2, 2), ("1k", 1000), ("2Ki", 2048), ("4000m", 4), ("0", 0), (" 3 ", 3)])
def test_quantities(value, expected):
    assert parse_quantity(value) == expected


@pytest.mark.parametrize("value", ["1.5", "1500m", "-1", "abc", None, True, [], "1" * 30])
def test_invalid_quantities(value):
    with pytest.raises((TypeError, ValueError)):
        parse_quantity(value)


def test_limit_only_gpu_count_uses_limit():
    found = list(iter_gpu_containers([pod("p", container(limits={"nvidia.com/gpu": "4"}))]))
    assert found[0].gpus == 4


def test_request_only_gpu_count_uses_request():
    found = list(iter_gpu_containers([pod("p", container(requests={"nvidia.com/gpu": "3"}))]))
    assert found[0].gpus == 3


def test_infiniband_bad_container_falls_through_to_next_ib_container():
    errors: list[Exception] = []
    item = pod("job", container(image=7, limits=IB), container(name="w2", image="fixture/train:1", limits=IB))
    assert list(iter_infiniband_pods([item], errors=errors)) == [("ns", "job", "fixture/train:1", 2)]
    assert len(errors) == 1


def test_infiniband_suffixed_quantity_is_kept():
    item = pod("job", container(limits={"rdma/ib": "1", "nvidia.com/gpu": "1k"}))
    assert list(iter_infiniband_pods([item])) == [("ns", "job", "fixture/model:1", 1000)]


# ── Nebius callers ───────────────────────────────────────────────────────


@pytest.fixture
def neb_kubectl(monkeypatch):
    calls: list[tuple] = []

    def install(items, returncode=0, stdout=None):
        def run(*args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=returncode, stdout=stdout if stdout is not None else json.dumps({"items": items}), stderr="")

        monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
        monkeypatch.setattr(nebius, "_kubectl_get_all_pods", run)

    install.calls = calls
    return install


def test_nebius_non_dict_pod_element_keeps_neighbors(neb_kubectl):
    neb_kubectl([pod("a", container(limits=GPU)), "junk", pod("b", container(limits=IB))])
    agents, warnings = nebius._discover_k8s_gpu_pods("k", "p")
    assert [a.name for a in agents] == ["nebius-k8s-gpu:ns/a", "nebius-k8s-gpu:ns/b"]
    assert len(warnings) == 1 and warnings[0].startswith("nebius:k8s-gpu-pods:unavailable:")
    agents, warnings = nebius._discover_infiniband_jobs("k", "p")
    assert [a.name for a in agents] == ["nebius-training:ns/b"]
    assert len(warnings) == 1 and warnings[0].startswith("nebius:infiniband-jobs:unavailable:")


@pytest.mark.parametrize("payload", [{"items": "x"}, {"items": None}, {}, []])
def test_nebius_malformed_envelope_still_fails_whole_read(neb_kubectl, payload):
    neb_kubectl([], stdout=json.dumps(payload))
    agents, warnings = nebius._discover_k8s_gpu_pods("k", "p")
    assert agents == []
    assert len(warnings) == 1 and warnings[0].startswith("nebius:k8s-gpu-pods:unavailable:")


def test_nebius_bad_container_keeps_later_gpu_container(neb_kubectl):
    neb_kubectl([pod("multi", container(name="bad", image=7, limits=GPU), container(name="good", limits=GPU))])
    agents, warnings = nebius._discover_k8s_gpu_pods("k", "p")
    assert [s.name for s in agents[0].mcp_servers] == ["nebius-k8s-gpu:ns/multi/good"]
    assert len(warnings) == 1


def test_nebius_limit_only_version_reports_real_gpu_count(neb_kubectl):
    neb_kubectl([pod("lim", container(limits={"nvidia.com/gpu": "2"}))])
    agents, _ = nebius._discover_k8s_gpu_pods("k", "p")
    assert agents[0].version == "gpu-request:2"


def test_nebius_unnamed_pods_do_not_merge(neb_kubectl):
    first, second = pod("x", container(limits=GPU)), pod("y", container(image="fixture/other:2", limits=GPU))
    del first["metadata"]["name"], second["metadata"]["name"]
    neb_kubectl([first, second])
    agents, warnings = nebius._discover_k8s_gpu_pods("k", "p")
    assert agents == []
    assert len(warnings) == 2


def test_nebius_discover_lists_pods_once_and_records_context(neb_kubectl, monkeypatch):
    for stage in ("_discover_ai_studio", "_discover_gpu_instances", "_discover_container_services"):
        monkeypatch.setattr(nebius, stage, lambda *a, **k: ([], []))
    neb_kubectl([pod("a", container(limits=GPU)), pod("b", container(limits=IB))])
    agents, warnings = nebius.discover(api_key="k", project_id="p", kube_context="team ctx")
    assert warnings == []
    assert len(neb_kubectl.calls) == 1
    assert neb_kubectl.calls[0] == ("team ctx",)
    origins = {a.name: a.metadata["cloud_origin"] for a in agents}
    assert {o["scope"]["cluster"] for o in origins.values()} == {"team ctx"}
    assert {a.config_path for a in agents} == {
        "nebius://p/k8s-gpu/team%20ctx/ns/a",
        "nebius://p/k8s-gpu/team%20ctx/ns/b",
        "nebius://p/training/team%20ctx/ns/b",
    }


def test_nebius_context_env_var(neb_kubectl, monkeypatch):
    for stage in ("_discover_ai_studio", "_discover_gpu_instances", "_discover_container_services"):
        monkeypatch.setattr(nebius, stage, lambda *a, **k: ([], []))
    monkeypatch.setenv("NEBIUS_KUBE_CONTEXT", "env-ctx")
    neb_kubectl([])
    assert nebius.discover(api_key="k", project_id="p") == ([], [])
    assert neb_kubectl.calls == [("env-ctx",)]


def test_nebius_kubectl_command_pins_context(monkeypatch):
    run = MagicMock(return_value=subprocess.CompletedProcess([], 0, stdout="{}", stderr=""))
    monkeypatch.setattr(nebius.subprocess, "run", run)
    nebius._kubectl_get_all_pods("ctx")
    assert run.call_args.args[0] == ["kubectl", "--context", "ctx", "get", "pods", "-A", "-o", "json"]
    nebius._kubectl_get_all_pods(None)
    assert run.call_args.args[0] == ["kubectl", "get", "pods", "-A", "-o", "json"]


# ── CoreWeave callers ────────────────────────────────────────────────────


def test_coreweave_lists_pods_once_per_discover(monkeypatch):
    calls: list[list[str]] = []

    def fake(args, context=None, timeout=60):
        calls.append(args)
        if args[1] == "pods":
            return {"items": [pod("a", container(limits=GPU)), pod("b", container(limits=IB))]}
        return {"items": []}

    monkeypatch.setattr(coreweave.shutil, "which", lambda _: "/fixture/kubectl")
    monkeypatch.setattr(coreweave, "_kubectl", fake)
    agents, warnings = coreweave.discover()
    assert warnings == []
    assert sum(1 for args in calls if args[1] == "pods") == 1
    assert sorted(a.source for a in agents) == ["coreweave-gpu", "coreweave-gpu", "coreweave-training"]


def test_coreweave_bad_container_keeps_later_container(monkeypatch):
    item = pod("multi", container(name="bad", image=7, limits=GPU), container(name="good", limits=GPU))
    monkeypatch.setattr(coreweave, "_kubectl", lambda *a, **k: {"items": [item, "junk"]})
    agents, warnings = coreweave._discover_gpu_pods(None, None)
    assert [a.name for a in agents] == ["coreweave-gpu-pod:ns/multi"]
    assert agents[0].metadata["containers"] == [{"name": "good", "image": "fixture/model:1"}]
    assert len(warnings) == 2
    assert all("Assessment incomplete" in w for w in warnings)
