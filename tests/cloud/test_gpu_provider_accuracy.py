"""GPU inventory retains deployment identity and reports missing evidence."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from agent_bom.cloud import coreweave
from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.k8s_gpu_common import iter_gpu_containers


def _pod(name: str, namespace: str = "production") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "containers": [{"name": "inference", "image": "registry.example/model:1", "resources": {"limits": {"nvidia.com/gpu": 1}}}]
        },
    }


def test_same_image_preserves_every_deployment() -> None:
    pods = [_pod("inference-a"), _pod("inference-b"), _pod("inference-a", "staging")]
    rows = list(iter_gpu_containers(pods))
    assert {(row[0], row[1]) for row in rows} == {("production", "inference-a"), ("production", "inference-b"), ("staging", "inference-a")}


def test_same_image_preserves_distinct_containers() -> None:
    pod = _pod("inference")
    pod["spec"]["containers"].append({**pod["spec"]["containers"][0], "name": "batch"})
    assert len(list(iter_gpu_containers([pod]))) == 2


@pytest.mark.parametrize("collector", [coreweave._discover_virtual_servers, coreweave._discover_inference_services])
def test_coreweave_denial_remains_visible(collector) -> None:
    with patch.object(coreweave, "_kubectl", side_effect=CloudDiscoveryError("permission_denied")):
        agents, warnings = collector("test-cluster", None)
    assert not agents
    assert warnings and "permission_denied" in warnings[0]


def test_coreweave_kubectl_failure_does_not_expose_stderr() -> None:
    result = subprocess.CompletedProcess([], 1, stdout="", stderr="Forbidden: token=private-test-value /private/kubeconfig")
    with patch.object(coreweave.subprocess, "run", return_value=result), pytest.raises(CloudDiscoveryError) as caught:
        coreweave._kubectl(["get", "pods"], context="test-cluster")
    assert "permission_denied" in str(caught.value)
    assert "private-test-value" not in str(caught.value)
    assert "/private/kubeconfig" not in str(caught.value)


def test_virtual_server_query_uses_the_published_crd_group() -> None:
    # CoreWeave publishes VirtualServer under group virtualservers.coreweave.com.
    with patch.object(coreweave, "_kubectl", return_value={"items": []}) as kubectl:
        coreweave._discover_virtual_servers("test-cluster", None)
    assert kubectl.call_args.args[0][:2] == ["get", "virtualservers.virtualservers.coreweave.com"]


def test_declared_permissions_match_the_queried_resources() -> None:
    captured: dict = {}
    with (
        patch.object(coreweave, "_kubectl", return_value={"items": []}),
        patch.object(coreweave, "attach_envelope_to_agents", side_effect=lambda agents, **kw: captured.update(kw)),
    ):
        coreweave.discover(context="test-cluster")
    declared = set(captured["permissions_used"])
    assert "kube:virtualservers.virtualservers.coreweave.com:list" in declared
    # Training jobs are read from pods; the batch Jobs API is never queried.
    assert "kube:jobs.batch:list" not in declared
