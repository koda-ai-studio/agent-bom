"""Workload inventory from Kubernetes manifests and Helm charts."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_bom.k8s_inventory_manifests import k8s_inventory_from_paths

_MANIFEST = """\
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels:
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    spec:
      serviceAccountName: web-sa
      containers:
        - name: app
          image: registry.example.test/shop/web:1.4
          envFrom:
            - secretRef:
                name: api-keys
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: web-edit
  namespace: shop
roleRef:
  kind: ClusterRole
  name: edit
subjects:
  - kind: ServiceAccount
    name: web-sa
    namespace: shop
"""


def test_manifest_directory_builds_one_inventory(tmp_path: Path) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "app.yaml").write_text(_MANIFEST)
    (tmp_path / "notes.yaml").write_text("just: data\n")

    inventory, notes = k8s_inventory_from_paths([str(tmp_path)])

    assert inventory is not None
    assert inventory["source"] == "manifest"
    assert [(w["kind"], w["name"]) for w in inventory["workloads"]] == [("Deployment", "web")]
    assert inventory["workloads"][0]["secret_refs"] == [{"name": "api-keys", "via": "envFrom"}]
    assert inventory["namespaces"][0]["labels"] == {"pod-security.kubernetes.io/enforce": "privileged"}
    [grant] = inventory["rbac_grants"]
    assert grant["secrets"]["access"] == "all"
    assert inventory["manifest_files"] == ["deploy/app.yaml"]
    assert notes == []


def test_paths_without_kubernetes_objects_give_no_inventory(tmp_path: Path) -> None:
    (tmp_path / "values.yaml").write_text("replicaCount: 1\n")
    (tmp_path / "broken.yaml").write_text("apiVersion: v1\nkind: [unclosed\n")
    inventory, _notes = k8s_inventory_from_paths([str(tmp_path)])
    assert inventory is None


def test_chart_without_helm_is_named_not_silently_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n")
    (chart / "templates" / "deploy.yaml").write_text("kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n")
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    inventory, notes = k8s_inventory_from_paths([str(tmp_path)])

    assert inventory is None
    assert notes == ["chart: helm not on PATH; its workloads are not in the Kubernetes inventory"]


def test_rendered_chart_contributes_workloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.iac import helm_templates

    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n")
    (chart / "templates" / "deploy.yaml").write_text("{{ .Values.x }}\n")
    rendered = "---\n# Source: web/templates/deploy.yaml\n" + _MANIFEST.split("---\n", 1)[1]
    monkeypatch.setattr(helm_templates, "render_chart", lambda _root: (rendered, ""))

    inventory, notes = k8s_inventory_from_paths([str(tmp_path)])

    assert inventory is not None and notes == []
    assert [(w["kind"], w["name"]) for w in inventory["workloads"]] == [("Deployment", "web")]
    assert inventory["helm_charts"] == ["chart"]
