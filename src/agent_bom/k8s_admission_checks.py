"""Read-only admission-control posture: Pod Security Admission levels and admission policies.

Evaluates objects that were already read (never written): namespace
``pod-security.kubernetes.io/enforce`` labels, ValidatingAdmissionPolicies and
their bindings (``admissionregistration.k8s.io/v1``), and validating admission
webhook configurations. Mappings use CIS Kubernetes Benchmark recommendation
5.2.1 ("at least one active policy control mechanism") where it applies;
fail-open and audit-only findings carry no CIS mapping because none matches.

The cluster-wide "no mechanism" finding is only raised when every admission
object kind was actually readable, so a denied read can never become a finding
or a pass.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.iac.models import IaCFinding

PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"
ADMISSION_RESOURCES = ("namespaces", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "validatingwebhookconfigurations")
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
_ENFORCING_LEVELS = frozenset({"baseline", "restricted"})
_CIS_POLICY = ["CIS-K8s-5.2.1", "NIST-CM-7"]


def _finding(rule_id: str, severity: str, title: str, message: str, ref: str, compliance: list[str]) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=ref,
        line_number=1,
        category="kubernetes-live",
        compliance=compliance,
    )


def _items(payload: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    items = (payload or {}).get("items") or []
    return [item for item in items if isinstance(item, Mapping)]


def _name(obj: Mapping[str, Any]) -> str:
    return str((obj.get("metadata") or {}).get("name") or "unknown")


def psa_enforce_issue(name: str, labels: Mapping[str, Any]) -> tuple[str, str] | None:
    """``("missing" | "privileged", message)`` for a non-system namespace, else ``None``."""
    if name in SYSTEM_NAMESPACES:
        return None
    level = str(labels.get(PSA_ENFORCE_LABEL) or "").strip().lower()
    if not level:
        return "missing", (
            f"Namespace '{name}' runs workloads but sets no {PSA_ENFORCE_LABEL} label, so Pod Security Admission "
            "enforces nothing there. Label it baseline or restricted."
        )
    if level == "privileged":
        return "privileged", (
            f"Namespace '{name}' enforces the privileged Pod Security level, which allows host namespaces, "
            "privileged containers and hostPath mounts. Enforce baseline or restricted."
        )
    return None


def _namespace_findings(namespaces: Iterable[Mapping[str, Any]], workload_namespaces: set[str]) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for namespace in namespaces:
        name = _name(namespace)
        if name not in workload_namespaces:
            continue
        issue = psa_enforce_issue(name, (namespace.get("metadata") or {}).get("labels") or {})
        if issue is None:
            continue
        kind, message = issue
        rule, title = (
            ("K8S-ADM-001", "Namespace has no Pod Security Admission enforce level")
            if kind == "missing"
            else ("K8S-ADM-002", "Namespace enforces the privileged Pod Security level")
        )
        findings.append(_finding(rule, "medium", title, message, f"k8s://namespace/{name}", _CIS_POLICY))
    return findings


def _denying(binding: Mapping[str, Any]) -> bool:
    actions = (binding.get("spec") or {}).get("validationActions") or []
    return "Deny" in actions


def _policy_findings(policies: list[Mapping[str, Any]], bindings: list[Mapping[str, Any]]) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for binding in bindings:
        if not _denying(binding):
            findings.append(
                _finding(
                    "K8S-ADM-005",
                    "low",
                    "ValidatingAdmissionPolicy binding never denies",
                    f"ValidatingAdmissionPolicyBinding '{_name(binding)}' only warns or audits (validationActions has no Deny), "
                    "so violating requests are still admitted.",
                    f"k8s://validatingadmissionpolicybinding/{_name(binding)}",
                    [],
                )
            )
    for policy in policies:
        if str((policy.get("spec") or {}).get("failurePolicy") or "") == "Ignore":
            findings.append(
                _finding(
                    "K8S-ADM-006",
                    "medium",
                    "ValidatingAdmissionPolicy fails open",
                    f"ValidatingAdmissionPolicy '{_name(policy)}' sets failurePolicy: Ignore, so a policy evaluation error "
                    "admits the request. Use Fail.",
                    f"k8s://validatingadmissionpolicy/{_name(policy)}",
                    [],
                )
            )
    return findings


def _webhook_findings(configurations: list[Mapping[str, Any]]) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for config in configurations:
        open_hooks = sorted(
            str(hook.get("name") or "")
            for hook in config.get("webhooks") or []
            if isinstance(hook, Mapping) and hook.get("failurePolicy") == "Ignore"
        )
        if open_hooks:
            findings.append(
                _finding(
                    "K8S-ADM-007",
                    "medium",
                    "Validating admission webhook fails open",
                    f"ValidatingWebhookConfiguration '{_name(config)}' has webhook(s) {open_hooks} with failurePolicy: Ignore; "
                    "if the webhook is unreachable, requests it should validate are admitted.",
                    f"k8s://validatingwebhookconfiguration/{_name(config)}",
                    [],
                )
            )
    return findings


def _has_mechanism(namespaces: list[Mapping[str, Any]], bindings: list[Mapping[str, Any]], webhooks: list[Mapping[str, Any]]) -> bool:
    enforcing = any(
        str(((ns.get("metadata") or {}).get("labels") or {}).get(PSA_ENFORCE_LABEL) or "").lower() in _ENFORCING_LEVELS for ns in namespaces
    )
    return enforcing or any(_denying(binding) for binding in bindings) or bool(webhooks)


def evaluate_admission_posture(
    *,
    namespaces: Mapping[str, Any] | None,
    workload_namespaces: set[str],
    validating_policies: Mapping[str, Any] | None = None,
    validating_policy_bindings: Mapping[str, Any] | None = None,
    validating_webhooks: Mapping[str, Any] | None = None,
    admission_evaluated: bool,
) -> list[IaCFinding]:
    """Admission findings for the objects read; see the module docstring for the rules."""
    ns_items, bindings, webhooks = _items(namespaces), _items(validating_policy_bindings), _items(validating_webhooks)
    findings = _namespace_findings(ns_items, workload_namespaces)
    findings.extend(_policy_findings(_items(validating_policies), bindings))
    findings.extend(_webhook_findings(webhooks))
    if admission_evaluated and workload_namespaces - SYSTEM_NAMESPACES and not _has_mechanism(ns_items, bindings, webhooks):
        findings.append(
            _finding(
                "K8S-ADM-004",
                "high",
                "No active admission policy control mechanism",
                "No namespace enforces a baseline or restricted Pod Security level, no ValidatingAdmissionPolicy binding "
                "denies, and no validating admission webhook is configured, so nothing stops a privileged pod from being admitted.",
                "k8s://cluster/admission",
                _CIS_POLICY,
            )
        )
    return findings
