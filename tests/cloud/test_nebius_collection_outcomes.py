"""Denied, throttled and malformed Nebius reads cannot claim empty coverage."""

import json
from types import SimpleNamespace

import httpx
import pytest

from agent_bom.cloud import nebius

REST_STAGES = [
    (nebius._discover_ai_studio, "ai-studio"),
    (nebius._discover_gpu_instances, "instances"),
    (nebius._discover_container_services, "containers"),
]
K8S_STAGES = [(nebius._discover_k8s_gpu_pods, "k8s-gpu-pods"), (nebius._discover_infiniband_jobs, "infiniband-jobs")]


@pytest.mark.parametrize("stage,resource", REST_STAGES)
@pytest.mark.parametrize("status,expected", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_rest_status_is_explicit(monkeypatch, stage, resource, status, expected):
    response = httpx.Response(status, text="private-marker", request=httpx.Request("GET", "https://example.test/private-marker"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)
    agents, warnings = stage("fixture", "fixture-project")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"nebius:{resource}:{expected}:")
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


@pytest.mark.parametrize("stage,resource", K8S_STAGES)
@pytest.mark.parametrize(
    "stderr,expected",
    [
        ("Forbidden private-marker", "denied"),
        ("Unauthorized private-marker", "denied"),
        ("TooManyRequests private-marker", "throttled"),
        ("unknown private-marker", "unavailable"),
    ],
)
def test_kubectl_failure_is_classified_without_stderr(monkeypatch, stage, resource, stderr, expected):
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=1, stderr=stderr))
    agents, warnings = stage("fixture", "fixture-project")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"nebius:{resource}:{expected}:")
    assert "private-marker" not in warnings[0]


@pytest.mark.parametrize("stage,resource", K8S_STAGES)
@pytest.mark.parametrize("payload", [{}, {"items": None}, {"items": "bad"}, {"items": [None]}, {"error": "private-marker"}])
def test_kubectl_malformed_success_is_incomplete(monkeypatch, stage, resource, payload):
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=0, stdout=json.dumps(payload)))
    agents, warnings = stage("fixture", "fixture-project")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"nebius:{resource}:unavailable:")


@pytest.mark.parametrize("stage,resource", K8S_STAGES)
def test_kubectl_explicit_empty_is_complete(monkeypatch, stage, resource):
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=0, stdout='{"items": []}'))
    assert stage("fixture", "fixture-project") == ([], [])


def test_failed_rest_stage_retains_other_inventory(monkeypatch):
    def request(*args, **kwargs):
        url = args[2]
        if "compute.api" in url:
            return httpx.Response(403, request=httpx.Request("GET", "https://example.test"))
        payload = {"models": [{"id": "fixture-model"}]} if "api.ai" in url else {"containers": []}
        return httpx.Response(200, json=payload, request=httpx.Request("GET", "https://example.test"))

    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", request)
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=0, stdout='{"items": []}'))
    agents, warnings = nebius.discover(api_key="fixture", project_id="fixture-project")
    assert [a.name for a in agents] == ["nebius-ai-studio:fixture-model"]
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:instances:denied:")


def test_unexpected_stage_failure_is_fixed_and_scoped(monkeypatch):
    def fail(*args):
        raise RuntimeError("private-marker")

    monkeypatch.setattr(nebius, "_discover_ai_studio", fail)
    for name in ("_discover_gpu_instances", "_discover_container_services", "_discover_k8s_gpu_pods", "_discover_infiniband_jobs"):
        monkeypatch.setattr(nebius, name, lambda *a, **k: ([], []))
    agents, warnings = nebius.discover(api_key="fixture", project_id="fixture-project")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:ai-studio:unavailable:")
    assert "private-marker" not in warnings[0]
