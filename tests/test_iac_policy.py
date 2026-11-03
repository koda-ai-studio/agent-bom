"""Policy-as-code for IaC: allow / warn / block by rule, resource, labels and environment."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.exceptions import parse_ignore_entries
from agent_bom.iac.models import ScanContext, iac_findings_payload
from agent_bom.iac.policy import IaCPolicy
from agent_bom.policy import _validate_policy, evaluate_policy, load_policy

POD = """apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    env: {env}
spec:
  containers:
    - name: app
      image: nginx:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext:
{marker}        privileged: true
"""

EXAMPLE = {
    "name": "iac-guardrails",
    "environments": {"prod": ["deploy/prod/**"], "dev": ["deploy/dev/**"]},
    "rules": [
        {
            "id": "no-privileged-prod",
            "description": "Privileged pods are blocked in prod",
            "iac_rule": "K8S-001",
            "iac_environment": "prod",
            "action": "block",
        },
        {
            "id": "privileged-dev-warn",
            "description": "Privileged pods in dev are reviewed",
            "iac_rule": "K8S-001",
            "iac_environment": "dev",
            "action": "warn",
        },
    ],
}


def _pod(root: Path, rel: str, *, name: str = "api", namespace: str = "default", env: str = "none", marker: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(POD.format(name=name, namespace=namespace, env=env, marker=marker))


def _scan(root: Path, policy: dict, entries: list[dict] | None = None):
    _validate_policy(policy)
    ctx = ScanContext(
        policy=IaCPolicy.from_policy(policy),
        exceptions=tuple(parse_ignore_entries(entries or [], origin="ignore.yaml")),
        today=date(2026, 11, 2),
    )
    return scan_iac_with_context(root, ctx)


def test_example_blocks_privileged_in_prod_and_warns_in_dev(tmp_path: Path) -> None:
    _pod(tmp_path, "deploy/prod/pod.yaml")
    _pod(tmp_path, "deploy/dev/pod.yaml")
    result = _scan(tmp_path, EXAMPLE)
    policy = result.policy_result
    assert policy is not None
    assert [(v["rule_id"], v["file_path"], v["environment"]) for v in policy["failures"]] == [
        ("no-privileged-prod", "deploy/prod/pod.yaml", "prod")
    ]
    assert [(v["rule_id"], v["environment"]) for v in policy["warnings"]] == [("privileged-dev-warn", "dev")]
    assert policy["passed"] is False
    failure = policy["failures"][0]
    assert failure["resource"]["kind"] == "Pod"
    assert failure["scope"] == "iac"


def test_environment_falls_back_to_resource_labels(tmp_path: Path) -> None:
    _pod(tmp_path, "k8s/pod.yaml", env="prod")
    result = _scan(tmp_path, {"rules": EXAMPLE["rules"]})
    assert [v["environment"] for v in result.policy_result["failures"]] == ["prod"]


def test_unknown_environment_matches_no_environment_rule(tmp_path: Path) -> None:
    _pod(tmp_path, "k8s/pod.yaml", env="")
    result = _scan(tmp_path, {"rules": EXAMPLE["rules"]})
    assert result.policy_result["violations"] == []


def test_namespace_label_and_kind_conditions(tmp_path: Path) -> None:
    _pod(tmp_path, "k8s/a.yaml", name="a", namespace="payments")
    _pod(tmp_path, "k8s/b.yaml", name="b", namespace="tools")
    rule = {
        "id": "pci",
        "iac_rule": "K8S-*",
        "severity_gte": "CRITICAL",
        "iac_namespace": "pay*",
        "iac_resource_kind": "pod",
        "action": "block",
    }
    result = _scan(tmp_path, {"rules": [rule]})
    assert {(v["iac_rule_id"], v["file_path"]) for v in result.policy_result["failures"]} == {("K8S-001", "k8s/a.yaml")}


def test_allow_rule_is_an_audited_exception(tmp_path: Path) -> None:
    _pod(tmp_path, "deploy/dev/pod.yaml")
    policy = {
        **EXAMPLE,
        "rules": [
            {
                "id": "dev-debug-ok",
                "iac_rule": "K8S-001",
                "iac_environment": "dev",
                "action": "allow",
                "reason": "dev debug pods",
                "owner": "platform",
            },
            *EXAMPLE["rules"],
        ],
    }
    result = _scan(tmp_path, policy)
    assert [f.rule_id for f in result.suppressed] == ["K8S-001"]
    record = result.suppressed[0].suppression
    assert (record["source"], record["reason"], record["owner"]) == ("policy", "dev debug pods", "platform")
    assert record["origin"] == "policy:iac-guardrails#dev-debug-ok"
    assert result.policy_result["warnings"] == []
    assert result.policy_result["allowed"][0]["rule_id"] == "dev-debug-ok"


def test_non_waivable_block_rejects_repo_local_exceptions(tmp_path: Path) -> None:
    _pod(tmp_path, "deploy/prod/pod.yaml", marker="        # agent-bom: ignore[K8S-001] we need host access\n")
    policy = {**EXAMPLE, "rules": [{**EXAMPLE["rules"][0], "waivable": False}]}
    result = _scan(tmp_path, policy)
    assert result.suppressed == []
    assert "K8S-001" in [f.rule_id for f in result.findings]
    assert [n.kind for n in result.notices] == ["rejected"]
    assert result.policy_result["passed"] is False


def test_waivable_block_honors_an_exception(tmp_path: Path) -> None:
    _pod(tmp_path, "deploy/prod/pod.yaml")
    result = _scan(tmp_path, EXAMPLE, [{"rule": "K8S-001", "path": "deploy/prod/*", "reason": "node agent", "owner": "sre"}])
    assert result.policy_result["passed"] is True
    assert [f.rule_id for f in result.suppressed] == ["K8S-001"]


def test_non_waivable_block_keeps_an_approved_tenant_exception(tmp_path: Path) -> None:
    from agent_bom.iac.exceptions import IaCException

    _pod(tmp_path, "deploy/prod/pod.yaml")
    tenant = IaCException(
        rule="K8S-001", reason="approved CAB-12", source="tenant", origin="exc-1", path="deploy/prod/*", approved_by="ciso"
    )
    policy = {**EXAMPLE, "rules": [{**EXAMPLE["rules"][0], "waivable": False}]}
    _validate_policy(policy)
    result = scan_iac_with_context(tmp_path, ScanContext(policy=IaCPolicy.from_policy(policy), exceptions=(tenant,)))
    assert result.policy_result["passed"] is True
    assert result.suppressed[0].suppression["approved_by"] == "ciso"


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ({"id": "r", "iac_rule": "K8S-001", "action": "deny"}, "action"),
        ({"id": "r", "iac_rule": "K8S-001", "action": "allow"}, "reason"),
        ({"id": "r", "iac_rule": "*", "action": "allow", "reason": "all"}, "scope"),
        ({"id": "r", "iac_rule": "K8S-001", "action": "warn", "waivable": False}, "waivable"),
        ({"id": "r", "iac_rule": "K8S-001", "iac_labels": ["env"]}, "iac_labels"),
        ({"id": "r", "iac_rule": "K8S-001", "colour": "red"}, "colour"),
        ({"id": "r", "iac_rule": "K8S-001", "severity_gte": "SEVERE"}, "severity_gte"),
        ({"iac_rule": "K8S-001", "action": "block"}, "id"),
        ({"id": "r", "iac_rule": "K8S-001", "action": "allow", "reason": "x", "expires": "soon"}, "expires"),
    ],
)
def test_invalid_iac_rules_are_rejected_at_load(rule: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_policy({"rules": [rule]})


def test_environments_must_be_path_globs() -> None:
    with pytest.raises(ValueError, match="environments"):
        _validate_policy({"environments": ["prod"], "rules": []})


def test_allow_and_block_are_only_for_iac_rules() -> None:
    with pytest.raises(ValueError, match="action"):
        _validate_policy({"rules": [{"id": "r", "severity_gte": "HIGH", "action": "allow"}]})


def test_iac_rules_never_match_vulnerabilities() -> None:
    from agent_bom.models import BlastRadius, Package, Severity, Vulnerability

    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-1", summary="x", severity=Severity.CRITICAL),
        package=Package(name="p", version="1", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    result = evaluate_policy({"rules": [{"id": "r", "iac_rule": "K8S-*", "severity_gte": "HIGH", "action": "block"}]}, [br])
    assert result["violations"] == []
    assert result["passed"] is True


def test_evaluate_policy_folds_in_the_scan_time_iac_outcome(tmp_path: Path) -> None:
    from agent_bom.models import AIBOMReport

    _pod(tmp_path, "deploy/prod/pod.yaml")
    result = _scan(tmp_path, EXAMPLE)
    report = AIBOMReport(agents=[], blast_radii=[])
    report.iac_findings_data = iac_findings_payload(result.findings, result.suppressed, result.notices, policy=result.policy_result)
    outcome = evaluate_policy(EXAMPLE, [], report=report)
    assert outcome["passed"] is False
    assert [v["rule_id"] for v in outcome["failures"]] == ["no-privileged-prod"]
    dry = evaluate_policy(EXAMPLE, [], report=report, dry_run=True)
    assert dry["passed"] is True


def test_load_policy_accepts_the_documented_example(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(EXAMPLE))
    assert load_policy(str(path))["name"] == "iac-guardrails"
