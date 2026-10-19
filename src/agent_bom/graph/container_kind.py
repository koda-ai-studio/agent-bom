"""Image or workload: the subtype a ``container`` node carries as ``container_kind``.

An image is an artifact (registry image, SBOM subject); a workload is what runs
it (pod, deployment, task). Both are ``EntityType.CONTAINER``; the subtype is
read only from fields a producer recorded, never from labels.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

IMAGE = "image"
WORKLOAD = "workload"
IMAGE_RESOURCE_TYPES = frozenset({"container_image", "image", "ecr_image"})
WORKLOAD_RESOURCE_TYPES = frozenset(
    {"deployment", "pod", "statefulset", "daemonset", "replicaset", "job", "cronjob", "workload", "ecs_task", "task"}
)


def _text(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def container_kind(attributes: Mapping[str, Any]) -> str:
    """``image``, ``workload`` or ``""`` when nothing recorded says which."""
    recorded = _text(attributes.get("container_kind"))
    if recorded in {IMAGE, WORKLOAD}:
        return recorded
    kind = _text(attributes.get("resource_type")) or _text(attributes.get("asset_type"))
    if kind in IMAGE_RESOURCE_TYPES:
        return IMAGE
    if kind in WORKLOAD_RESOURCE_TYPES or _text(attributes.get("kubernetes_kind")):
        return WORKLOAD
    return ""


def container_kind_attributes(attributes: Mapping[str, Any]) -> dict[str, str]:
    """``{"container_kind": ...}`` when the subtype is recorded, else ``{}``."""
    kind = container_kind(attributes)
    return {"container_kind": kind} if kind else {}
