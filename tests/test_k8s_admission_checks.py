"""Read-only admission and Pod Security posture checks (live cluster and manifests)."""

from __future__ import annotations

from agent_bom.k8s_admission_checks import evaluate_admission_posture

_PSA = "pod-security.kubernetes.io/enforce"


def _ns(name: str, enforce: str | None = None, **labels: str) -> dict:
    merged = dict(labels)
    if enforce is not None:
        merged[_PSA] = enforce
    return {"metadata": {"name": name, "labels": merged}}


def _ids(findings: list) -> list[tuple[str, str]]:
    return sorted((f.rule_id, f.file_path) for f in findings)


def test_namespace_without_enforce_level_is_flagged_only_when_it_runs_workloads() -> None:
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("shop"), _ns("empty"), _ns("kube-system")]},
        workload_namespaces={"shop", "kube-system"},
        admission_evaluated=True,
    )
    assert ("K8S-ADM-001", "k8s://namespace/shop") in _ids(findings)
    assert not [f for f in findings if f.file_path.endswith("/empty")], "a namespace with no workloads is not flagged"
    assert not [f for f in findings if f.file_path.endswith("/kube-system")], "system namespaces are expected to be privileged"
    [f] = [f for f in findings if f.rule_id == "K8S-ADM-001"]
    assert f.compliance[0] == "CIS-K8s-5.2.1"
    assert f.severity == "medium"


def test_privileged_enforce_level_is_flagged_and_restricted_is_clean() -> None:
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("legacy", "privileged"), _ns("shop", "restricted"), _ns("ops", "baseline")]},
        workload_namespaces={"legacy", "shop", "ops"},
        admission_evaluated=True,
    )
    assert _ids(findings) == [("K8S-ADM-002", "k8s://namespace/legacy")]


def test_cluster_with_no_policy_mechanism_at_all_is_one_cluster_finding() -> None:
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("shop")]},
        workload_namespaces={"shop"},
        validating_policy_bindings={"items": []},
        validating_webhooks={"items": []},
        admission_evaluated=True,
    )
    cluster = [f for f in findings if f.rule_id == "K8S-ADM-004"]
    assert len(cluster) == 1 and cluster[0].severity == "high"


def test_a_baseline_namespace_or_a_validating_webhook_counts_as_a_mechanism() -> None:
    for namespaces, webhooks in (
        ([_ns("shop", "baseline")], []),
        ([_ns("shop")], [{"metadata": {"name": "policy-engine"}, "webhooks": []}]),
    ):
        findings = evaluate_admission_posture(
            namespaces={"items": namespaces},
            workload_namespaces={"shop"},
            validating_webhooks={"items": webhooks},
            admission_evaluated=True,
        )
        assert "K8S-ADM-004" not in {f.rule_id for f in findings}


def test_a_validating_admission_policy_binding_counts_as_a_mechanism() -> None:
    binding = {"metadata": {"name": "require-limits"}, "spec": {"policyName": "limits", "validationActions": ["Deny"]}}
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("shop")]},
        workload_namespaces={"shop"},
        validating_policy_bindings={"items": [binding]},
        validating_webhooks={"items": []},
        admission_evaluated=True,
    )
    assert "K8S-ADM-004" not in {f.rule_id for f in findings}


def test_audit_only_binding_and_fail_open_policy_are_reported() -> None:
    binding = {"metadata": {"name": "warn-only"}, "spec": {"policyName": "p", "validationActions": ["Warn", "Audit"]}}
    policy = {"metadata": {"name": "p"}, "spec": {"failurePolicy": "Ignore"}}
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("shop", "restricted")]},
        workload_namespaces={"shop"},
        validating_policies={"items": [policy]},
        validating_policy_bindings={"items": [binding]},
        admission_evaluated=True,
    )
    assert _ids(findings) == [
        ("K8S-ADM-005", "k8s://validatingadmissionpolicybinding/warn-only"),
        ("K8S-ADM-006", "k8s://validatingadmissionpolicy/p"),
    ]


def test_fail_open_webhook_is_reported_and_fail_closed_is_not() -> None:
    webhooks = {
        "items": [
            {"metadata": {"name": "policy-engine"}, "webhooks": [{"name": "validate.policy.example.test", "failurePolicy": "Ignore"}]},
            {"metadata": {"name": "strict"}, "webhooks": [{"name": "v.example.test", "failurePolicy": "Fail"}]},
        ]
    }
    findings = evaluate_admission_posture(
        namespaces={"items": [_ns("shop", "baseline")]},
        workload_namespaces={"shop"},
        validating_webhooks=webhooks,
        admission_evaluated=True,
    )
    assert _ids(findings) == [("K8S-ADM-007", "k8s://validatingwebhookconfiguration/policy-engine")]


def test_unevaluated_admission_objects_never_produce_the_cluster_wide_finding() -> None:
    findings = evaluate_admission_posture(namespaces={"items": [_ns("shop")]}, workload_namespaces={"shop"}, admission_evaluated=False)
    assert "K8S-ADM-004" not in {f.rule_id for f in findings}


def test_manifest_namespaces_get_the_same_pod_security_rules() -> None:
    from agent_bom.iac.kubernetes import scan_k8s_text

    text = (
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: shop\n---\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: legacy\n  labels:\n    pod-security.kubernetes.io/enforce: privileged\n---\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: safe\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n---\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kube-system\n"
    )
    findings = [f for f in scan_k8s_text(text, "ns.yaml") if f.rule_id in {"K8S-037", "K8S-038"}]
    assert sorted((f.rule_id, f.line_number) for f in findings) == [("K8S-037", 3), ("K8S-038", 11)]
    assert all(f.compliance[0] == "CIS-K8s-5.2.1" for f in findings)
    assert "runs workloads" not in findings[0].message


def test_live_posture_reads_admission_objects_and_records_their_collectors() -> None:
    from agent_bom.k8s import CollectorState, K8sPostureStatus, scan_live_cluster_posture_with_evidence
    from agent_bom.k8s_transport import K8sReadResult, K8sTransportError

    pod = {"metadata": {"name": "web", "namespace": "shop"}, "spec": {"containers": [{"name": "c"}]}, "status": {"phase": "Running"}}
    payloads = {"pods": {"items": [pod]}, "namespaces": {"items": [_ns("shop")]}}

    class _Transport:
        name = "fixture"

        def list_resource(self, resource: str, *, namespace: str | None = None, all_namespaces: bool = False) -> K8sReadResult:
            if resource == "validatingadmissionpolicies":
                raise K8sTransportError("the server could not find the requested resource", status_code=404)
            data = payloads.get(resource, {"items": []})
            return K8sReadResult(data=data, object_count=len(data["items"]), pages=1, truncated=False)

        def close(self) -> None:
            return None

    result = scan_live_cluster_posture_with_evidence(namespace="shop", transport=_Transport())  # type: ignore[arg-type]

    evidence = {c.collector_id: c.state for c in result.collectors}
    assert evidence["namespaces"] is CollectorState.EXECUTED
    assert evidence["validatingadmissionpolicies"] is CollectorState.UNEVALUABLE
    assert result.status is K8sPostureStatus.PARTIAL
    rule_ids = {f.rule_id for f in result.findings}
    assert "K8S-ADM-001" in rule_ids
    assert "K8S-ADM-004" not in rule_ids, "an unreadable admission kind can never prove there is no mechanism"
