"""Manifest rules and live pod posture agree on the same pod spec.

Kubernetes resolves ``runAsUser``/``runAsNonRoot`` from the container
securityContext first and the pod securityContext otherwise; ``privileged``
and ``allowPrivilegeEscalation`` exist only on the container.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from agent_bom.iac.kubernetes import scan_k8s_text
from agent_bom.kubernetes.posture_checks import evaluate_pod_security

# static rule id -> live rule id for the shared securityContext checks
PAIRS = {"K8S-001": "K8S-LIVE-007", "K8S-005": "K8S-LIVE-011", "K8S-009": "K8S-LIVE-012"}

SPECS: dict[str, tuple[dict[str, Any], dict[str, Any], set[str]]] = {
    # name: (pod securityContext, container securityContext, expected static rules)
    "pod_level_root": ({"runAsUser": 0}, {}, {"K8S-005"}),
    "pod_level_root_container_override": ({"runAsUser": 0}, {"runAsUser": 1000}, set()),
    "container_root": ({}, {"runAsUser": 0}, {"K8S-005"}),
    "container_root_overrides_pod_user": ({"runAsUser": 1000}, {"runAsUser": 0}, {"K8S-005"}),
    "pod_non_root_false": ({"runAsNonRoot": False}, {}, {"K8S-005"}),
    "container_non_root_overrides_pod": ({"runAsNonRoot": False}, {"runAsNonRoot": True, "runAsUser": 1000}, set()),
    "privileged": ({"runAsNonRoot": True}, {"privileged": True}, {"K8S-001"}),
    "escalation": ({"runAsNonRoot": True}, {"allowPrivilegeEscalation": True}, {"K8S-009"}),
    "all_three": ({}, {"privileged": True, "allowPrivilegeEscalation": True, "runAsUser": 0}, {"K8S-001", "K8S-005", "K8S-009"}),
    "pod_level_privileged_is_not_a_field": ({"privileged": True, "allowPrivilegeEscalation": True}, {}, set()),
    "hardened": ({"runAsNonRoot": True, "runAsUser": 1000}, {"allowPrivilegeEscalation": False, "privileged": False}, set()),
    "bool_is_not_uid_zero": ({"runAsUser": False}, {}, set()),
}


def _pod_spec(pod_ctx: dict[str, Any], ctr_ctx: dict[str, Any]) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [{"name": "app", "image": "nginx:1.25", "securityContext": ctr_ctx}]}
    if pod_ctx:
        spec["securityContext"] = pod_ctx
    return spec


def _static(spec: dict[str, Any]) -> dict[str, Any]:
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {"template": {"metadata": {"labels": {"app": "web"}}, "spec": spec}},
    }
    findings = scan_k8s_text(yaml.safe_dump(doc), "deploy.yaml")
    return {f.rule_id: f for f in findings if f.rule_id in PAIRS}


def _live(spec: dict[str, Any]) -> dict[str, Any]:
    pod = {"metadata": {"name": "web-1", "namespace": "prod"}, "spec": spec, "status": {"phase": "Running"}}
    findings = evaluate_pod_security({"items": [pod]})
    return {f.rule_id: f for f in findings if f.rule_id in PAIRS.values()}


@pytest.mark.parametrize("name", list(SPECS))
def test_static_and_live_flag_the_same_security_context(name: str) -> None:
    pod_ctx, ctr_ctx, expected = SPECS[name]
    spec = _pod_spec(pod_ctx, ctr_ctx)
    static, live = _static(spec), _live(spec)
    assert set(static) == expected
    assert set(live) == {PAIRS[rule] for rule in expected}
    for rule in expected:
        s, lv = static[rule], live[PAIRS[rule]]
        assert (s.severity, s.compliance, s.attack_techniques) == (lv.severity, lv.compliance, lv.attack_techniques), rule


def test_privileged_container_carries_escape_technique_in_both() -> None:
    spec = _pod_spec({}, {"privileged": True})
    assert _static(spec)["K8S-001"].attack_techniques == ["T1611"]
    assert _live(spec)["K8S-LIVE-007"].attack_techniques == ["T1611"]


def test_pod_level_root_points_at_the_pod_security_context_line() -> None:
    text = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsUser: 0
      containers:
        - name: app
          image: nginx:1.25
"""
    [finding] = [f for f in scan_k8s_text(text, "deploy.yaml") if f.rule_id == "K8S-005"]
    assert finding.line_number == 9
    assert "pod" in finding.message
