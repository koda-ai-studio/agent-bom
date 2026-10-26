"""Read-only Kubernetes posture evaluators over parsed API payloads.

Pure functions: each takes an already-collected ``kubectl``/API JSON payload and
returns findings. Collection lives in :mod:`agent_bom.k8s`.
"""

from __future__ import annotations

from collections.abc import Callable

from agent_bom.iac.models import IaCFinding

# Capabilities whose runtime presence materially widens the host attack surface.
_DANGEROUS_CAPABILITIES = frozenset({"NET_RAW", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"})

# Durations that mean "no idle timeout" for the kubelet streaming connection.
_ZERO_DURATIONS = frozenset({"0", "0s", "0m", "0h", "0m0s", "0h0m0s"})


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    message: str,
    file_path: str,
    compliance: list[str],
    attack_techniques: list[str] | None = None,
) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=file_path,
        line_number=1,
        category="kubernetes-live",
        compliance=compliance,
        attack_techniques=list(attack_techniques or []),
    )


def _pod_containers(spec: dict) -> list[dict]:
    """Return all container specs (containers + initContainers) from a pod spec."""
    containers = spec.get("containers", []) or []
    init_containers = spec.get("initContainers", []) or []
    return [c for c in list(containers) + list(init_containers) if isinstance(c, dict)]


def _host_namespace_findings(spec: dict, ns: str, name: str, pod_ref: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    if spec.get("hostNetwork") is True:
        findings.append(
            _finding(
                "K8S-LIVE-008",
                "high",
                "Running pod uses host network",
                f"Pod '{ns}/{name}' is running with hostNetwork: true. It shares the node's "
                "network namespace, allowing traffic sniffing and NetworkPolicy bypass.",
                pod_ref,
                ["CIS-K8s-5.2.4", "NIST-CM-7"],
            )
        )
    if spec.get("hostPID") is True or spec.get("hostIPC") is True:
        shared = ", ".join(k for k in ("hostPID", "hostIPC") if spec.get(k) is True)
        findings.append(
            _finding(
                "K8S-LIVE-009",
                "high",
                "Running pod shares host process/IPC namespace",
                f"Pod '{ns}/{name}' is running with {shared}: true. Sharing the host PID/IPC "
                "namespace enables container escape and cross-process attacks.",
                pod_ref,
                ["CIS-K8s-5.2.2", "NIST-CM-7"],
            )
        )
    for vol in spec.get("volumes", []) or []:
        if isinstance(vol, dict) and vol.get("hostPath"):
            host_path = (vol.get("hostPath") or {}).get("path", "unknown")
            findings.append(
                _finding(
                    "K8S-LIVE-010",
                    "high",
                    "Running pod mounts a host path",
                    f"Pod '{ns}/{name}' mounts host path '{host_path}' via volume "
                    f"'{vol.get('name', 'unknown')}'. hostPath mounts break container isolation "
                    "and can expose or tamper with node files.",
                    pod_ref,
                    ["CIS-K8s-5.2.12", "NIST-SC-7"],
                )
            )
            break
    return findings


def _container_findings(container: dict, pod_sec_ctx: dict, ns: str, name: str, pod_ref: str) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    cname = container.get("name", "unnamed")
    sec_ctx = container.get("securityContext", {}) or {}
    where = f"Container '{cname}' in pod '{ns}/{name}'"
    if sec_ctx.get("privileged") is True:
        findings.append(
            _finding(
                "K8S-LIVE-007",
                "critical",
                "Running privileged container",
                f"{where} is running in privileged mode, granting full host access. Remove privileged: true from the workload.",
                pod_ref,
                ["CIS-K8s-5.2.1", "NIST-AC-6"],
                ["T1611"],
            )
        )
    # Kubernetes resolves runAsUser / runAsNonRoot at the container level,
    # falling back to the pod-level securityContext when the container does not
    # set them, so a pod-level root setting is inherited into the container.
    effective_run_as_user = sec_ctx.get("runAsUser", pod_sec_ctx.get("runAsUser"))
    effective_run_as_non_root = sec_ctx.get("runAsNonRoot", pod_sec_ctx.get("runAsNonRoot"))
    if effective_run_as_user == 0 or effective_run_as_non_root is False:
        findings.append(
            _finding(
                "K8S-LIVE-011",
                "high",
                "Running container executes as root",
                f"{where} is running as root (runAsUser: 0 or runAsNonRoot: false, at the container or inherited "
                "pod level). Run as a non-root user to limit exploit impact.",
                pod_ref,
                ["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )
    if sec_ctx.get("allowPrivilegeEscalation") is True:
        findings.append(
            _finding(
                "K8S-LIVE-012",
                "high",
                "Running container allows privilege escalation",
                f"{where} allows privilege escalation. Set allowPrivilegeEscalation: false to block setuid-based escalation.",
                pod_ref,
                ["CIS-K8s-5.2.5", "NIST-AC-6"],
            )
        )
    add_caps = (sec_ctx.get("capabilities", {}) or {}).get("add", []) or []
    dangerous = sorted({c.upper() for c in add_caps if isinstance(c, str)} & _DANGEROUS_CAPABILITIES)
    if dangerous:
        findings.append(
            _finding(
                "K8S-LIVE-013",
                "critical",
                "Running container adds dangerous capabilities",
                f"{where} adds capabilities {dangerous}. Drop ALL capabilities and add back only what the workload needs.",
                pod_ref,
                ["CIS-K8s-5.2.8", "NIST-AC-6"],
            )
        )
    return findings


def _running_pod_findings(pod: dict, default_namespace: str) -> list[IaCFinding]:
    metadata = pod.get("metadata", {}) or {}
    name = metadata.get("name", "unknown")
    ns = metadata.get("namespace", default_namespace)
    pod_ref = f"k8s://{ns}/{name}"
    spec = pod.get("spec", {}) or {}
    findings = _host_namespace_findings(spec, ns, name, pod_ref)
    pod_sec_ctx = spec.get("securityContext", {}) or {}
    for container in _pod_containers(spec):
        findings.extend(_container_findings(container, pod_sec_ctx, ns, name, pod_ref))
    if not spec.get("securityContext"):
        findings.append(
            _finding(
                "K8S-LIVE-014",
                "medium",
                "Running pod has no securityContext",
                f"Pod '{ns}/{name}' is running without a pod-level securityContext. Set "
                "runAsNonRoot, fsGroup, and seccompProfile to enforce a hardened baseline.",
                pod_ref,
                ["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )
    return findings


def evaluate_pod_security(pods: dict, default_namespace: str = "default") -> list[IaCFinding]:
    """Evaluate PodSecurity posture across *running* workloads.

    Operates on a parsed ``kubectl get pods -o json`` payload. Only pods in the
    ``Running`` phase are evaluated — this is a runtime posture check, not a
    manifest lint, so pending/terminated pods are ignored. Findings mirror the
    severities and CIS/NIST mappings of the static manifest scanner
    (:mod:`agent_bom.iac.kubernetes`).
    """
    findings: list[IaCFinding] = []
    for pod in pods.get("items", []) or []:
        if isinstance(pod, dict) and (pod.get("status", {}) or {}).get("phase") == "Running":
            findings.extend(_running_pod_findings(pod, default_namespace))
    return findings


def _rule_has_wildcard(rule: dict) -> bool:
    """Return True if an RBAC policy rule grants wildcard verbs or resources."""
    verbs = rule.get("verbs", []) or []
    resources = rule.get("resources", []) or []
    return "*" in verbs or "*" in resources


def _is_builtin_role(name: str) -> bool:
    """Built-in roles (cluster-admin, system:*) are expected wildcards."""
    return name == "cluster-admin" or name == "admin" or name.startswith("system:")


def _has_wildcard_rule(role: dict) -> bool:
    return any(_rule_has_wildcard(r) for r in (role.get("rules", []) or []) if isinstance(r, dict))


def _cluster_admin_binding_findings(cluster_role_bindings: dict) -> list[IaCFinding]:
    findings: list[IaCFinding] = []
    for binding in cluster_role_bindings.get("items", []) or []:
        if not isinstance(binding, dict) or (binding.get("roleRef", {}) or {}).get("name") != "cluster-admin":
            continue
        subjects = binding.get("subjects", []) or []
        subject_names = (
            ", ".join(
                f"{s.get('kind', 'Subject')}:{s.get('namespace', '')}/{s.get('name', 'unknown')}".strip("/")
                for s in subjects
                if isinstance(s, dict)
            )
            or "unknown subject"
        )
        binding_name = (binding.get("metadata", {}) or {}).get("name", "unknown")
        findings.append(
            _finding(
                "K8S-LIVE-006",
                "critical",
                "Live cluster-admin RBAC binding detected",
                f"ClusterRoleBinding '{binding_name}' grants cluster-admin to {subject_names}. "
                "Review live RBAC drift and replace with least-privilege bindings.",
                f"k8s://clusterrolebinding/{binding_name}",
                ["CIS-K8s-5.1.1", "NIST-AC-6"],
            )
        )
    return findings


_WILDCARD_ADVICE = (
    "grants wildcard (*) verbs or resources. Wildcard grants violate least-privilege — enumerate the specific verbs/resources required."
)


def evaluate_rbac(
    cluster_roles: dict,
    roles: dict,
    cluster_role_bindings: dict,
    default_namespace: str = "default",
) -> list[IaCFinding]:
    """Audit live RBAC for over-broad grants.

    Flags ClusterRoleBindings to ``cluster-admin`` and user-defined
    Cluster/Roles that grant wildcard verbs or resources. Built-in
    ``cluster-admin`` and ``system:*`` roles are intentionally skipped — their
    wildcards are expected and cannot be tightened.
    """
    findings = _cluster_admin_binding_findings(cluster_role_bindings)
    for role in cluster_roles.get("items", []) or []:
        if not isinstance(role, dict):
            continue
        name = (role.get("metadata", {}) or {}).get("name", "unknown")
        if not _is_builtin_role(name) and _has_wildcard_rule(role):
            findings.append(
                _finding(
                    "K8S-LIVE-015",
                    "high",
                    "ClusterRole grants wildcard permissions",
                    f"ClusterRole '{name}' {_WILDCARD_ADVICE}",
                    f"k8s://clusterrole/{name}",
                    ["CIS-K8s-5.1.3", "NIST-AC-6"],
                )
            )
    for role in roles.get("items", []) or []:
        if not isinstance(role, dict):
            continue
        metadata = role.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        ns = metadata.get("namespace", default_namespace)
        if not name.startswith("system:") and _has_wildcard_rule(role):
            findings.append(
                _finding(
                    "K8S-LIVE-016",
                    "high",
                    "Role grants wildcard permissions",
                    f"Role '{ns}/{name}' {_WILDCARD_ADVICE}",
                    f"k8s://role/{ns}/{name}",
                    ["CIS-K8s-5.1.3", "NIST-AC-6"],
                )
            )
    return findings


# (rule id, severity, title, compliance, predicate, message suffix builder)
_KubeletCheck = tuple[str, str, str, list[str], Callable[[dict], bool], Callable[[dict], str]]


def _read_only_port(config: dict) -> bool:
    port = config.get("readOnlyPort")
    return isinstance(port, int) and port != 0


_KUBELET_CHECKS: tuple[_KubeletCheck, ...] = (
    (
        "K8S-LIVE-020",
        "critical",
        "Kubelet allows anonymous authentication",
        ["CIS-K8s-4.2.1", "NIST-AC-6"],
        lambda c: ((c.get("authentication", {}) or {}).get("anonymous", {}) or {}).get("enabled") is True,
        lambda _c: (
            "has authentication.anonymous.enabled: true. Anonymous requests to the kubelet API can read pod data "
            "and exec into containers. Set --anonymous-auth=false."
        ),
    ),
    (
        "K8S-LIVE-021",
        "critical",
        "Kubelet authorization mode is AlwaysAllow",
        ["CIS-K8s-4.2.2", "NIST-AC-6"],
        lambda c: (c.get("authorization", {}) or {}).get("mode") == "AlwaysAllow",
        lambda _c: "uses authorization.mode: AlwaysAllow, which grants every authenticated request. Set --authorization-mode=Webhook.",
    ),
    (
        "K8S-LIVE-022",
        "high",
        "Kubelet read-only port is enabled",
        ["CIS-K8s-4.2.4", "NIST-AC-6"],
        _read_only_port,
        lambda c: (
            f"exposes readOnlyPort {c.get('readOnlyPort')}. This unauthenticated port leaks pod and node metadata. Set --read-only-port=0."
        ),
    ),
    (
        "K8S-LIVE-023",
        "medium",
        "Kubelet streaming connections never time out",
        ["CIS-K8s-4.2.5", "NIST-AC-12"],
        lambda c: str(c.get("streamingConnectionIdleTimeout", "")).strip().lower() in _ZERO_DURATIONS,
        lambda _c: (
            "sets streamingConnectionIdleTimeout to 0 (disabled). Idle exec/attach/port-forward streams are held "
            "open indefinitely. Set a non-zero timeout (e.g. 4h)."
        ),
    ),
    (
        "K8S-LIVE-024",
        "medium",
        "Kubelet does not protect kernel defaults",
        ["CIS-K8s-4.2.6", "NIST-CM-6"],
        lambda c: c.get("protectKernelDefaults") is False,
        lambda _c: "has protectKernelDefaults: false, so it may overwrite hardened kernel sysctls. Set --protect-kernel-defaults=true.",
    ),
    (
        "K8S-LIVE-025",
        "low",
        "Kubelet does not manage iptables util chains",
        ["CIS-K8s-4.2.7", "NIST-SC-7"],
        lambda c: c.get("makeIPTablesUtilChains") is False,
        lambda _c: (
            "has makeIPTablesUtilChains: false. Enable it so the kubelet maintains the iptables rules that back NetworkPolicy enforcement."
        ),
    ),
    (
        "K8S-LIVE-026",
        "medium",
        "Kubelet client certificate rotation is disabled",
        ["CIS-K8s-4.2.10", "NIST-IA-5"],
        lambda c: c.get("rotateCertificates") is False,
        lambda _c: (
            "has rotateCertificates: false. Long-lived client certificates widen the credential-theft window. "
            "Set --rotate-certificates=true."
        ),
    ),
)


def evaluate_kubelet_config(node_name: str, kubelet_config: dict) -> list[IaCFinding]:
    """Evaluate a node's kubelet configuration against CIS Benchmark section 4.2.

    ``kubelet_config`` is the resolved KubeletConfiguration (v1beta1) returned
    by the fine-grained ``/api/v1/nodes/<node>/configz`` subresource. Only
    fields present in the resolved config are evaluated; absent optional fields
    are not fabricated into a pass or fail.
    """
    node_ref = f"k8s://node/{node_name}"
    return [
        _finding(rule_id, severity, title, f"Kubelet on node '{node_name}' {message(kubelet_config)}", node_ref, compliance)
        for rule_id, severity, title, compliance, applies, message in _KUBELET_CHECKS
        if applies(kubelet_config)
    ]
