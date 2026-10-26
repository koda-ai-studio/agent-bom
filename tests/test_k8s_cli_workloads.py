"""``agent-bom scan --k8s`` end to end: live inventory → image scan → JSON → graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import EntityType
from agent_bom.k8s_transport import K8sReadResult, _resource_path
from agent_bom.models import Package, Severity, Vulnerability

_DIGEST = "sha256:" + "e" * 64
_PINNED = f"registry.example.test/shop/web@{_DIGEST}"
_POD_SPEC = {
    "serviceAccountName": "web-sa",
    "containers": [{"name": "app", "image": "registry.example.test/shop/web:1.4", "envFrom": [{"secretRef": {"name": "api-keys"}}]}],
}
_RECORDED: dict[str, list[dict[str, Any]]] = {
    "namespaces": [{"metadata": {"name": "shop"}}],
    "deployments": [{"metadata": {"name": "web", "namespace": "shop"}, "spec": {"template": {"spec": _POD_SPEC}}}],
    "pods": [
        {
            "metadata": {"name": "web-a", "namespace": "shop", "uid": "pod-a", "ownerReferences": [{"kind": "Deployment", "name": "web"}]},
            "spec": _POD_SPEC,
            "status": {"containerStatuses": [{"name": "app", "imageID": _PINNED}]},
        }
    ],
    "rolebindings": [
        {
            "metadata": {"name": "web-edit", "namespace": "shop"},
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
            "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}],
        }
    ],
}


class _Transport:
    name = "kubectl"

    def list_resource(self, resource: str, *, namespace: str | None = None, all_namespaces: bool = False) -> K8sReadResult:
        _resource_path(resource, namespace, all_namespaces)
        items = _RECORDED.get(resource, [])
        return K8sReadResult(data={"items": items}, object_count=len(items), pages=1, truncated=False)

    def close(self) -> None:
        return None


@pytest.fixture
def k8s_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    scanned: list[str] = []

    def fake_scan_image(ref: str, **_kwargs: Any) -> tuple[list[Package], str]:
        scanned.append(ref)
        vuln = Vulnerability(id="CVE-2099-0002", summary="test", severity=Severity.CRITICAL)
        return [Package(name="openssl", version="3.0.1", ecosystem="deb", vulnerabilities=[vuln])], "fake"

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("agent_bom.k8s_transport.select_k8s_transport", lambda **_kwargs: _Transport())
    monkeypatch.setattr("agent_bom.image.scan_image", fake_scan_image)
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", lambda *args, **kwargs: [])
    return scanned


def test_k8s_scan_json_carries_the_workload_inventory_and_builds_the_graph(k8s_cli: list[str], tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "--k8s", "--namespace", "shop", "--no-discover", "-f", "json", "-o", str(out), "-q"])
    assert result.exit_code in {0, 1}, result.output

    assert k8s_cli == [_PINNED], "the running digest is what gets scanned"
    report = json.loads(out.read_text())
    section = report["kubernetes_inventory"]
    [inventory] = section["inventories"]
    [workload] = inventory["workloads"]
    assert (workload["kind"], workload["namespace"], workload["name"]) == ("Deployment", "shop", "web")
    scan = workload["containers"][0]["scan"]
    assert scan == {"scanned": True, "packages": 1, "vulnerabilities": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
    assert section["summary"]["workloads_with_vulnerabilities"] == 1
    assert inventory["collection"]["status"] == "complete"

    graph = build_unified_graph_from_report(report)
    workload_id = "container:k8s:workload:current-context/shop/deployment/web"
    assert graph.nodes[workload_id].attributes["container_kind"] == "workload"
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVER]
    paths = _derived_attack_paths(graph)
    assert [p for p in paths if p.target == "vuln:CVE-2099-0002" and workload_id in p.hops]
    pivot = [p for p in paths if p.source == workload_id and p.target.startswith("credential:k8s:secret:")]
    assert pivot and pivot[0].vuln_ids == ["CVE-2099-0002"]


def test_k8s_scan_console_shows_the_workload_table(k8s_cli: list[str]) -> None:
    result = CliRunner().invoke(main, ["scan", "--k8s", "--namespace", "shop", "--no-discover", "-f", "console"])
    assert result.exit_code in {0, 1}, result.output
    assert "1 workload(s) in 1 namespace(s)" in result.output
    assert "Kubernetes workloads" in result.output
    assert "shop/deployment/web" in result.output
    assert "reads secrets" in result.output
