"""Pod Security Admission namespace levels, shared by live posture and manifest rules."""

from __future__ import annotations

from collections.abc import Mapping
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
