"""Shared contexts and line-lookup helpers for the Kubernetes manifest rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_bom.iac.yaml_lines import key_line, node_line


@dataclass(frozen=True)
class K8sDocument:
    """One YAML document of a manifest."""

    doc: dict[str, Any]
    kind: Any
    name: Any
    name_lower: str
    content: str
    rel_path: str


@dataclass(frozen=True)
class K8sWorkload:
    """A workload document with a resolved pod spec."""

    kind: Any
    name: Any
    namespace: Any
    pod_spec: dict[str, Any]
    content: str
    rel_path: str
    metadata_line: int = 1


@dataclass(frozen=True)
class K8sContainer:
    """One container (or init container) of a workload."""

    workload: K8sWorkload
    container: dict[str, Any]
    cname: Any
    sec_ctx: dict[str, Any]


def find_line(content: str, key: str, value: Any, start_line: int = 1) -> int:
    """Best-effort line number search for a key-value pair in YAML text."""
    if isinstance(value, bool):
        val_str = "true" if value else "false"
    elif isinstance(value, int):
        val_str = str(value)
    else:
        val_str = str(value)
    pattern = rf"{re.escape(key)}\s*:\s*{re.escape(val_str)}"
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(pattern, line):
            return i
    return start_line


def find_key_line(content: str, key: str, start_line: int = 1) -> int:
    """Best-effort line number search for a key in YAML text."""
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(rf"\b{re.escape(key)}\s*:", line):
            return i
    return start_line


def container_line(c: K8sContainer) -> int:
    """Line where the container's list item starts (its ``- name:`` line)."""
    return node_line(c.container) or node_line(c.workload.pod_spec) or 1


def container_key_line(c: K8sContainer, key: str) -> int:
    """Line of ``key`` in the container, else the container's own line."""
    return key_line(c.container, key) if key in c.container else container_line(c)


def security_context_line(c: K8sContainer, key: str) -> int:
    """Line of ``key`` in the container securityContext, then the pod's, else the container line."""
    if key in c.sec_ctx:
        return key_line(c.sec_ctx, key)
    pod_ctx = c.workload.pod_spec.get("securityContext") or {}
    if isinstance(pod_ctx, dict) and key in pod_ctx:
        return key_line(pod_ctx, key)
    return container_key_line(c, "securityContext")


def pod_spec_line(workload: K8sWorkload, key: str | None = None) -> int:
    """Line of ``key`` in the pod spec, else the pod spec's own line."""
    spec = workload.pod_spec
    if key is not None and key in spec:
        return key_line(spec, key)
    return node_line(spec) or 1
