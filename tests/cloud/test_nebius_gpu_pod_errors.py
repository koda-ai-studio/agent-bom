"""Malformed Nebius GPU pods must not erase independent inventory."""

import json
from types import SimpleNamespace

import pytest

from agent_bom.cloud import nebius


def pod(name):
    return {
        "metadata": {"name": name, "namespace": "inference"},
        "spec": {"containers": [{"name": "model", "image": "fixture/model:1", "resources": {"limits": {"nvidia.com/gpu": "2"}}}]},
    }


def discover(monkeypatch, items):
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=0, stdout=json.dumps({"items": items})))
    return nebius._discover_k8s_gpu_pods("fixture", "fixture-project")


@pytest.mark.parametrize(
    "bad", [{"metadata": None}, {"spec": None}, {"spec": {"containers": [None]}}, {"metadata": {"name": []}, "spec": pod("bad")["spec"]}]
)
def test_bad_pod_preserves_neighbors(monkeypatch, bad):
    agents, warnings = discover(monkeypatch, [pod("first"), bad, pod("last")])
    assert [a.name for a in agents] == ["nebius-k8s-gpu:inference/first", "nebius-k8s-gpu:inference/last"]
    assert all(a.mcp_servers[0].packages[0].name == "fixture/model" for a in agents)
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:k8s-gpu-pods:unavailable:")
    assert "Assessment incomplete" in warnings[0]


def test_good_container_before_failure_is_retained(monkeypatch):
    item = pod("partial")
    item["spec"]["containers"].append(None)
    agents, warnings = discover(monkeypatch, [item, pod("last")])
    assert [a.name for a in agents] == ["nebius-k8s-gpu:inference/partial", "nebius-k8s-gpu:inference/last"]
    assert len(warnings) == 1


def test_init_and_regular_containers_still_share_one_workload(monkeypatch):
    item = pod("multi")
    item["spec"]["initContainers"] = [{**item["spec"]["containers"][0], "name": "init"}]
    agents, warnings = discover(monkeypatch, [item])
    assert len(agents) == 1
    assert len(agents[0].mcp_servers) == 2
    assert warnings == []


def test_empty_is_complete(monkeypatch):
    assert discover(monkeypatch, []) == ([], [])


def test_conversion_failure_keeps_other_pods_and_hides_details(monkeypatch):
    original = nebius._k8s_gpu_pod_agent

    def convert(project_id, namespace, name, containers, *rest):
        if name == "bad":
            raise ValueError("private-marker")
        return original(project_id, namespace, name, containers, *rest)

    monkeypatch.setattr(nebius, "_k8s_gpu_pod_agent", convert)
    agents, warnings = discover(monkeypatch, [pod("first"), pod("bad"), pod("last")])
    assert [a.name for a in agents] == ["nebius-k8s-gpu:inference/first", "nebius-k8s-gpu:inference/last"]
    assert len(warnings) == 1
    assert "private-marker" not in warnings[0]
