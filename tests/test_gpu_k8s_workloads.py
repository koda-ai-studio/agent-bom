"""Kubernetes GPU workloads from recorded read-only kubectl output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_bom.cloud.gpu_k8s_inventory import collect_k8s_gpu_inventory, workload_agent
from agent_bom.cloud.gpu_k8s_workloads import cluster_identity, node_contexts

FIXTURES = Path(__file__).parent / "fixtures" / "gpu_infra"
EKS_ARN = "arn:aws:eks:us-east-1:111122223333:cluster/ml-prod"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def recorded_kubectl(*, kubeconfig_cluster: str = EKS_ARN, policy: bool = True) -> Any:
    calls: list[list[str]] = []

    def run(args: list[str], context: str | None = None, timeout: int = 60) -> Any:
        calls.append(list(args))
        if args == ["get", "nodes"]:
            return _load("k8s_nodes.json")
        if args == ["get", "pods", "--all-namespaces"]:
            return _load("k8s_pods.json")
        if args == ["get", "clusterpolicies.nvidia.com"]:
            return _load("gpu_operator_clusterpolicy.json") if policy else None
        if args == ["config", "view", "--minify"]:
            return {
                "current-context": kubeconfig_cluster,
                "contexts": [{"name": kubeconfig_cluster, "context": {"cluster": kubeconfig_cluster}}],
            }
        raise AssertionError(f"unexpected kubectl call {args}")

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_only_reads_with_kubectl_get_and_config_view() -> None:
    runner = recorded_kubectl()
    collect_k8s_gpu_inventory(runner)
    assert all(call[0] in {"get", "config"} for call in runner.calls)
    assert all("exec" not in call and "apply" not in call for call in runner.calls)


def test_gpu_pods_are_bound_to_their_node_pool_and_cluster() -> None:
    inv = collect_k8s_gpu_inventory(recorded_kubectl())
    assert (inv.provider, inv.cluster_key) == ("aws", EKS_ARN)
    by_pod = {w.pod: w for w in inv.workloads}
    assert set(by_pod) == {"llm-inference-7d9f", "notebook-0", "train-job-x2k"}  # device plugin and web request no GPU
    llm = by_pod["llm-inference-7d9f"]
    assert (llm.pool_name, llm.gpu_count, llm.service_account) == ("gpu-a10g", 1, "llm-serving")
    assert llm.aws_role_arn == "arn:aws:iam::111122223333:role/llm-model-reader"
    assert llm.credential_env == ["HF_TOKEN"]
    assert llm.gpu_sharing == {"strategy": "time-slicing", "max_shared_clients": 4}
    assert llm.driver_version == "535.104.05"
    notebook = by_pod["notebook-0"]
    assert notebook.containers[0]["privileged"] is True and notebook.host_ipc is True
    assert notebook.host_paths == ["/var/lib/kubelet/device-plugins"]
    pending = by_pod["train-job-x2k"]
    assert (pending.pool_name, pending.node_name, pending.gpu_count) == ("train-custom", "", 8)
    assert (inv.stack.driver_version, inv.stack.toolkit_version) == ("535.104.05", "1.16.1")


def test_workload_agent_carries_image_and_gpu_stack_packages_with_cpes() -> None:
    inv = collect_k8s_gpu_inventory(recorded_kubectl())
    llm = next(w for w in inv.workloads if w.pod == "llm-inference-7d9f")
    agent = workload_agent(llm, inv.stack)
    (server,) = agent.mcp_servers
    by_name = {p.name: p for p in server.packages}
    assert by_name["nvidia-container-toolkit"].cpe == "cpe:2.3:a:nvidia:nvidia_container_toolkit:1.16.1:*:*:*:*:*:*:*"
    assert by_name["nvidia-gpu-display-driver"].version == "535.104.05"
    assert by_name["nvidia-gpu-display-driver"].discovery_provenance["source"] == "gpu-feature-discovery-label"
    assert by_name["nvidia-container-toolkit"].discovery_provenance["source"] == "gpu-operator-clusterpolicy"
    assert any(p.ecosystem == "container-image" for p in server.packages)
    assert server.env == {"HF_TOKEN": ""} and server.credential_names == ["HF_TOKEN"]
    origin = agent.metadata["cloud_origin"]
    assert (origin["provider"], origin["service"], origin["resource_type"]) == ("aws", "kubernetes", "gpu-workload")
    assert agent.metadata["gpu_workload"]["pool_name"] == "gpu-a10g"


def test_without_gpu_operator_no_toolkit_version_is_claimed() -> None:
    inv = collect_k8s_gpu_inventory(recorded_kubectl(policy=False))
    llm = next(w for w in inv.workloads if w.pod == "llm-inference-7d9f")
    names = {p.name for p in workload_agent(llm, inv.stack).mcp_servers[0].packages}
    assert "nvidia-container-toolkit" not in names and "nvidia-gpu-display-driver" in names


@pytest.mark.parametrize(
    ("cluster", "expected"),
    [
        (EKS_ARN, ("aws", EKS_ARN)),
        ("gke_example-ml-project_us-central1_vision", ("gcp", "projects/example-ml-project/locations/us-central1/clusters/vision")),
        ("aks-ml", ("aws", "kube-context:aks-ml")),
    ],
)
def test_cluster_identity_only_matches_provable_cloud_keys(cluster: str, expected: tuple[str, str]) -> None:
    kubeconfig = {"current-context": cluster, "contexts": [{"name": cluster, "context": {"cluster": cluster}}]}
    assert cluster_identity(kubeconfig, node_contexts(_load("k8s_nodes.json"))) == expected


def test_no_kubectl_degrades_to_a_warning() -> None:
    inv = collect_k8s_gpu_inventory(lambda *_a, **_k: None)
    assert inv.workloads == [] and inv.warnings
