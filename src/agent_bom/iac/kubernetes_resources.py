"""Kubernetes manifest rules for non-workload resources, pod specs and volumes."""

from __future__ import annotations

from typing import Any

from agent_bom.iac.kubernetes_common import K8sDocument, K8sWorkload, pod_spec_line
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.yaml_lines import item_line, key_line, node_line
from agent_bom.kubernetes.pod_security import PSA_ENFORCE_LABEL, psa_enforce_issue


def k8s_024(d: K8sDocument) -> list[IaCFinding]:
    """K8S-024: ServiceAccount with automountServiceAccountToken: true."""
    doc, name, rel_path = d.doc, d.name, d.rel_path
    findings: list[IaCFinding] = []
    if doc.get("automountServiceAccountToken") is True:
        findings.append(
            IaCFinding(
                rule_id="K8S-024",
                severity="medium",
                title="ServiceAccount auto-mounts token",
                message=(
                    f"ServiceAccount '{name}' sets automountServiceAccountToken: true. "
                    "Set to false and only mount tokens in pods that need API access."
                ),
                file_path=rel_path,
                line_number=key_line(doc, "automountServiceAccountToken", 1),
                category="kubernetes",
                compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
            )
        )
    return findings


def k8s_037_038(d: K8sDocument) -> list[IaCFinding]:
    """K8S-037: Namespace without a Pod Security enforce level; K8S-038: enforces privileged."""
    metadata = d.doc.get("metadata", {}) or {}
    labels = metadata.get("labels", {}) or {}
    labels = labels if isinstance(labels, dict) else {}
    issue = psa_enforce_issue(str(d.name), labels)
    if issue is None:
        return []
    kind, message = issue
    message = message.replace(" runs workloads but", "")
    compliance = ["CIS-K8s-5.2.1", "NIST-CM-7"]
    if kind == "missing":
        return [
            IaCFinding(
                rule_id="K8S-037",
                severity="medium",
                title="Namespace has no Pod Security Admission enforce level",
                message=message,
                file_path=d.rel_path,
                line_number=key_line(d.doc, "metadata", 1),
                category="kubernetes",
                compliance=compliance,
            )
        ]
    return [
        IaCFinding(
            rule_id="K8S-038",
            severity="medium",
            title="Namespace enforces the privileged Pod Security level",
            message=message,
            file_path=d.rel_path,
            line_number=key_line(labels, PSA_ENFORCE_LABEL, key_line(d.doc, "metadata", 1)),
            category="kubernetes",
            compliance=compliance,
        )
    ]


def k8s_025(d: K8sDocument) -> list[IaCFinding]:
    """K8S-025: ClusterRoleBinding with cluster-admin role."""
    doc, name, rel_path = d.doc, d.name, d.rel_path
    findings: list[IaCFinding] = []
    role_ref = doc.get("roleRef", {}) or {}
    if role_ref.get("name") == "cluster-admin":
        findings.append(
            IaCFinding(
                rule_id="K8S-025",
                severity="critical",
                title="ClusterRoleBinding grants cluster-admin",
                message=(
                    f"ClusterRoleBinding '{name}' binds to the cluster-admin role. "
                    "This grants full cluster access. Use least-privilege roles instead."
                ),
                file_path=rel_path,
                line_number=key_line(doc, "roleRef", 1),
                category="kubernetes",
                compliance=["CIS-K8s-5.1.1", "NIST-AC-6"],
            )
        )
    return findings


def k8s_036(d: K8sDocument) -> list[IaCFinding]:
    """K8S-036: nvidia-device-plugin ClusterRole with mutation verbs."""
    doc, name, rel_path, _name_lower, kind = d.doc, d.name, d.rel_path, d.name_lower, d.kind
    findings: list[IaCFinding] = []
    if kind == "ClusterRole" and "nvidia" in _name_lower and "device-plugin" in _name_lower:
        rules = doc.get("rules", []) or []
        _mutation_verbs = {"create", "delete", "update", "patch", "bind", "escalate", "impersonate"}
        for rule in rules:
            found_mutations = set(rule.get("verbs", []) or []) & _mutation_verbs
            if found_mutations:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-036",
                        severity="high",
                        title=f"nvidia-device-plugin ClusterRole '{name}' grants mutation verbs",
                        message=(
                            f"ClusterRole '{name}' includes mutation verbs {sorted(found_mutations)}. "
                            "The nvidia-device-plugin requires only get/list/watch permissions. "
                            "Remove mutation verbs to enforce least-privilege for the GPU device plugin."
                        ),
                        file_path=rel_path,
                        line_number=key_line(doc, "rules", 1),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.1.3", "NIST-AC-6"],
                        attack_techniques=["T1548"],
                    )
                )
                break
    return findings


def k8s_028(d: K8sDocument) -> list[IaCFinding]:
    """K8S-028: NetworkPolicy missing egress rules."""
    doc, name, rel_path = d.doc, d.name, d.rel_path
    findings: list[IaCFinding] = []
    spec = doc.get("spec", {}) or {}
    policy_types = spec.get("policyTypes", []) or []
    if "Egress" not in policy_types or not spec.get("egress"):
        findings.append(
            IaCFinding(
                rule_id="K8S-028",
                severity="medium",
                title="NetworkPolicy missing egress rules",
                message=(
                    f"NetworkPolicy '{name}' does not define egress rules. "
                    "Without egress rules, pods can reach any external endpoint. "
                    "Add egress rules to restrict outbound traffic."
                ),
                file_path=rel_path,
                line_number=key_line(doc, "spec", 1),
                category="kubernetes",
                compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
            )
        )
    return findings


def k8s_002(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-002: hostNetwork."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    if pod_spec.get("hostNetwork") is True:
        findings.append(
            IaCFinding(
                rule_id="K8S-002",
                severity="high",
                title="hostNetwork enabled",
                message=(
                    f"Resource '{name}' uses hostNetwork: true. "
                    "This shares the host's network namespace, allowing "
                    "traffic sniffing and bypass of network policies."
                ),
                file_path=rel_path,
                line_number=pod_spec_line(w, "hostNetwork"),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.4", "NIST-CM-7"],
            )
        )
    return findings


def k8s_003(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-003: hostPID / hostIPC."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    for host_key in ("hostPID", "hostIPC"):
        if pod_spec.get(host_key) is True:
            findings.append(
                IaCFinding(
                    rule_id="K8S-003",
                    severity="high",
                    title=f"{host_key} enabled",
                    message=(
                        f"Resource '{name}' uses {host_key}: true. "
                        "Sharing the host PID/IPC namespace allows container "
                        "escape and cross-process attacks."
                    ),
                    file_path=rel_path,
                    line_number=pod_spec_line(w, host_key),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.2", "NIST-CM-7"],
                )
            )
    return findings


def k8s_008(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-008: default namespace."""
    kind, name, namespace, rel_path = w.kind, w.name, w.namespace, w.rel_path
    findings: list[IaCFinding] = []
    if namespace == "default" or (not namespace and kind != "Pod"):
        findings.append(
            IaCFinding(
                rule_id="K8S-008",
                severity="medium",
                title="Using default namespace",
                message=(f"Resource '{name}' uses the default namespace. Use dedicated namespaces for workload isolation and RBAC."),
                file_path=rel_path,
                line_number=w.metadata_line,
                category="kubernetes",
                compliance=["CIS-K8s-5.7.1", "NIST-AC-4"],
            )
        )
    return findings


def k8s_010(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-010: automountServiceAccountToken."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(
            IaCFinding(
                rule_id="K8S-010",
                severity="medium",
                title="Service account token auto-mounted",
                message=(
                    f"Resource '{name}' does not set automountServiceAccountToken: false. "
                    "The default service account token is mounted into every pod, "
                    "enabling lateral movement if compromised."
                ),
                file_path=rel_path,
                line_number=pod_spec_line(w),
                category="kubernetes",
                compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
            )
        )
    return findings


def k8s_033(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-033: shareProcessNamespace: true."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    if pod_spec.get("shareProcessNamespace") is True:
        findings.append(
            IaCFinding(
                rule_id="K8S-033",
                severity="medium",
                title="shareProcessNamespace enabled",
                message=(
                    f"Resource '{name}' sets shareProcessNamespace: true. "
                    "All containers in the pod share the same PID namespace, "
                    "allowing them to signal each other's processes. "
                    "Only enable when explicitly required."
                ),
                file_path=rel_path,
                line_number=pod_spec_line(w, "shareProcessNamespace"),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.2", "NIST-CM-7"],
            )
        )
    return findings


def k8s_030(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-030: Deployment without PodAntiAffinity."""
    kind, name, pod_spec, rel_path = w.kind, w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    if kind == "Deployment":
        affinity = pod_spec.get("affinity", {}) or {}
        if not affinity.get("podAntiAffinity"):
            findings.append(
                IaCFinding(
                    rule_id="K8S-030",
                    severity="low",
                    title="Deployment without PodAntiAffinity",
                    message=(
                        f"Deployment '{name}' does not define podAntiAffinity. "
                        "Without anti-affinity, all replicas may be scheduled on the same node, "
                        "creating a single point of failure."
                    ),
                    file_path=rel_path,
                    line_number=pod_spec_line(w),
                    category="kubernetes",
                    compliance=["NIST-CP-10"],
                )
            )
    return findings


def k8s_014_019(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-019: emptyDir without sizeLimit / K8S-014: hostPath."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    volumes = pod_spec.get("volumes", []) or []
    for vol_index, vol in enumerate(volumes):
        if not isinstance(vol, dict):
            continue
        vol_line = item_line(volumes, vol_index, pod_spec_line(w, "volumes"))
        empty_dir = vol.get("emptyDir")
        if empty_dir is not None and not (isinstance(empty_dir, dict) and empty_dir.get("sizeLimit")):
            vol_name = vol.get("name", "unknown")
            findings.append(
                IaCFinding(
                    rule_id="K8S-019",
                    severity="low",
                    title=f"emptyDir '{vol_name}' without sizeLimit",
                    message=f"Volume '{vol_name}' uses emptyDir without sizeLimit. Set sizeLimit to prevent disk exhaustion.",
                    file_path=rel_path,
                    line_number=key_line(vol, "emptyDir", vol_line),
                    category="kubernetes",
                    compliance=["NIST-SC-6"],
                )
            )
        if vol.get("hostPath"):
            vol_name = vol.get("name", "unknown")
            findings.append(
                IaCFinding(
                    rule_id="K8S-014",
                    severity="high",
                    title=f"hostPath volume mount '{vol_name}'",
                    message=f"Volume '{vol_name}' mounts a host path. This breaks container isolation. Use PVCs instead.",
                    file_path=rel_path,
                    line_number=key_line(vol, "hostPath", vol_line),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.12", "NIST-SC-7"],
                )
            )
            # K8S-035: hostPath mounting NVIDIA device files exposes the GPU driver directly
            host_path_value = (vol.get("hostPath") or {}).get("path", "")
            if any(host_path_value.startswith(p) for p in ("/dev/nvidia", "/proc/driver/nvidia")):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-035",
                        severity="critical",
                        title=f"hostPath mounts NVIDIA device file '{host_path_value}'",
                        message=(
                            f"Volume '{vol_name}' in '{name}' mounts '{host_path_value}' "
                            "directly from the host. Exposing NVIDIA device files bypasses "
                            "container isolation and grants raw GPU hardware access. "
                            "Use the NVIDIA device plugin instead of hostPath mounts."
                        ),
                        file_path=rel_path,
                        line_number=key_line(vol, "hostPath", vol_line),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.12", "NIST-AC-6", "NIST-SI-3"],
                        attack_techniques=["T1611"],
                    )
                )
    return findings


def k8s_013(w: K8sWorkload) -> list[IaCFinding]:
    """K8S-013: No securityContext at pod level."""
    name, pod_spec, rel_path = w.name, w.pod_spec, w.rel_path
    findings: list[IaCFinding] = []
    if not pod_spec.get("securityContext"):
        findings.append(
            IaCFinding(
                rule_id="K8S-013",
                severity="medium",
                title="No securityContext at pod level",
                message=f"Pod '{name}' has no pod-level securityContext. Set runAsNonRoot, fsGroup, and seccompProfile.",
                file_path=rel_path,
                line_number=pod_spec_line(w),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )
    return findings


def k8s_021(docs: list[Any], content: str, rel_path: str) -> list[IaCFinding]:
    """K8S-021: Missing PodDisruptionBudget for Deployments."""
    findings: list[IaCFinding] = []
    # Collect Deployment names and PDB matchLabels from the same manifest
    deployment_names: dict[str, int] = {}
    pdb_selectors: set[str] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        dk = doc.get("kind", "")
        dm = doc.get("metadata", {}) or {}
        if dk == "Deployment":
            deployment_names.setdefault(dm.get("name", ""), key_line(dm, "name", node_line(doc, 1)))
        if dk == "PodDisruptionBudget":
            selector = doc.get("spec", {}).get("selector", {}) or {}
            match_labels = selector.get("matchLabels", {}) or {}
            # Track the app label value as a proxy for deployment name
            for _lbl_key, lbl_val in match_labels.items():
                pdb_selectors.add(lbl_val)

    for dep_name, dep_line in deployment_names.items():
        if dep_name and dep_name not in pdb_selectors:
            findings.append(
                IaCFinding(
                    rule_id="K8S-021",
                    severity="low",
                    title=f"No PodDisruptionBudget for Deployment '{dep_name}'",
                    message=(
                        f"Deployment '{dep_name}' has no matching PodDisruptionBudget "
                        "in the same manifest. A PDB ensures minimum availability "
                        "during voluntary disruptions like node drains."
                    ),
                    file_path=rel_path,
                    line_number=dep_line,
                    category="kubernetes",
                    compliance=["NIST-CP-10"],
                )
            )
    return findings
