"""Pod Security Admission levels and securityContext predicates shared by live posture and manifest rules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
ENFORCING_LEVELS = frozenset({"baseline", "restricted"})


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


# Shared securityContext predicates for manifest rules (K8S-001/005/009) and live
# posture (K8S-LIVE-007/011/012). Kubernetes: "If set, the fields of
# SecurityContext override the equivalent fields of PodSecurityContext";
# ``privileged`` and ``allowPrivilegeEscalation`` exist only on the container.


@dataclass(frozen=True)
class SecurityContextRule:
    severity: str
    compliance: tuple[str, ...]
    attack_techniques: tuple[str, ...] = ()


PRIVILEGED = SecurityContextRule("critical", ("CIS-K8s-5.2.1", "NIST-AC-6"), ("T1611",))
RUNS_AS_ROOT = SecurityContextRule("high", ("CIS-K8s-5.2.6", "NIST-AC-6"))
PRIVILEGE_ESCALATION = SecurityContextRule("high", ("CIS-K8s-5.2.5", "NIST-AC-6"))


def effective_setting(container_ctx: Mapping[str, Any], pod_ctx: Mapping[str, Any], key: str) -> Any:
    """The container's value for ``key``, else the pod's."""
    value = container_ctx.get(key)
    return pod_ctx.get(key) if value is None else value


def root_settings(container_ctx: Mapping[str, Any], pod_ctx: Mapping[str, Any]) -> list[str]:
    """Effective settings that run the container as root: ``runAsUser`` (0) and/or ``runAsNonRoot`` (false)."""
    user = effective_setting(container_ctx, pod_ctx, "runAsUser")
    found = ["runAsUser"] if isinstance(user, int) and not isinstance(user, bool) and user == 0 else []
    if effective_setting(container_ctx, pod_ctx, "runAsNonRoot") is False:
        found.append("runAsNonRoot")
    return found


def is_privileged(container_ctx: Mapping[str, Any]) -> bool:
    return container_ctx.get("privileged") is True


def allows_privilege_escalation(container_ctx: Mapping[str, Any]) -> bool:
    return container_ctx.get("allowPrivilegeEscalation") is True
