"""The shipped read-only scanner RBAC grants exactly what the Kubernetes collectors request.

Every resource the live inventory, posture and admission collectors list must be
readable (get/list) by the packaged reader role, or an in-cluster run reports
those collectors unevaluable. The role must never grant Secrets or a mutation
verb.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from agent_bom.k8s import _POSTURE_RESOURCES
from agent_bom.k8s_transport import CLUSTER_RESOURCES, NAMESPACED_RESOURCES
from agent_bom.kubernetes.admission_checks import ADMISSION_RESOURCES
from agent_bom.kubernetes.inventory_live import INVENTORY_RESOURCES

ROOT = Path(__file__).resolve().parents[1]
_READ = {"get", "list"}
_MUTATING = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate", "*"}


def _api_group(resource: str) -> str:
    path = NAMESPACED_RESOURCES[resource][0] if resource in NAMESPACED_RESOURCES else CLUSTER_RESOURCES[resource]
    return "" if path.startswith("/api/v1") else path.split("/")[2]


def _requested() -> set[tuple[str, str]]:
    resources = {*INVENTORY_RESOURCES, *_POSTURE_RESOURCES, *ADMISSION_RESOURCES}
    return {(_api_group(resource), resource) for resource in resources}


def _helm_rules() -> list[dict[str, Any]]:
    text = (ROOT / "deploy/helm/agent-bom/templates/rbac.yaml").read_text()
    block = text.split("rules:", 1)[1].split("---", 1)[0]
    return yaml.safe_load("rules:" + block)["rules"]


def _manifest_rules() -> list[dict[str, Any]]:
    docs = yaml.safe_load_all((ROOT / "deploy/k8s/rbac.yaml").read_text())
    return next(doc for doc in docs if doc and doc.get("kind") == "ClusterRole")["rules"]


@pytest.mark.parametrize("rules", [_helm_rules(), _manifest_rules()], ids=["helm", "manifest"])
def test_reader_role_covers_every_collector_read_and_nothing_more_dangerous(rules: list[dict[str, Any]]) -> None:
    granted = {
        (group, resource) for rule in rules if _READ <= set(rule["verbs"]) for group in rule["apiGroups"] for resource in rule["resources"]
    }
    missing = sorted(_requested() - granted)
    assert not missing, f"collectors request resources the reader role cannot list: {missing}"
    assert not any("secrets" in rule["resources"] or "*" in rule["resources"] for rule in rules)
    assert not any(_MUTATING & set(rule["verbs"]) for rule in rules)
