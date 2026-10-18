"""Shared images must not collapse distinct GPU workload observations."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from agent_bom.cloud.k8s_gpu_common import iter_gpu_containers
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json


def pod(namespace, name):
    return {
        "metadata": {"namespace": namespace, "name": name},
        "spec": {
            "containers": [{"name": "inference", "image": "vllm/vllm-openai:0.6.0", "resources": {"limits": {"nvidia.com/gpu": "1"}}}]
        },
    }


def test_shared_image_keeps_each_pod_and_namespace():
    pods = [pod("team-a", "replica-a"), pod("team-a", "replica-b"), pod("team-b", "replica-a")]
    rows = list(iter_gpu_containers(pods))
    assert {(namespace, name) for namespace, name, *_ in rows} == {
        ("team-a", "replica-a"),
        ("team-a", "replica-b"),
        ("team-b", "replica-a"),
    }


@pytest.mark.parametrize("provider", ["coreweave", "nebius"])
def test_provider_shared_image_workloads_survive_graph_projection(provider):
    pods = [pod("team-a", "replica-a"), pod("team-a", "replica-b"), pod("team-b", "replica-a")]
    with (
        patch("shutil.which", return_value="kubectl"),
        patch("subprocess.run", return_value=subprocess.CompletedProcess(["kubectl"], 0, json.dumps({"items": pods}), "")),
    ):
        if provider == "coreweave":
            from agent_bom.cloud.coreweave import _discover_gpu_pods

            agents, warnings = _discover_gpu_pods("owned-fixture", None)
        else:
            from agent_bom.cloud.nebius import _discover_k8s_gpu_pods

            agents, warnings = _discover_k8s_gpu_pods("fixture-key", "fixture-project")
    assert not warnings
    assert len(agents) == 3
    report = to_json(AIBOMReport(agents=agents))
    graph = build_unified_graph_from_report(report)
    resources = [node for node in graph.nodes.values() if node.attributes.get("resource_type") == "gpu-pod"]
    assert len(resources) == 3
    assert {node.attributes["resource_id"] for node in resources} == {"team-a/replica-a", "team-a/replica-b", "team-b/replica-a"}
