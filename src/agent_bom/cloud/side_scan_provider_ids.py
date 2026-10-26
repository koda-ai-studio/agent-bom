"""Parse provider resource ids, tags and labels for the side-scan lifecycle adapters."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _tags(resource: Any) -> dict[str, str]:
    raw = resource.get("tags") if isinstance(resource, Mapping) else getattr(resource, "tags", None)
    return {str(key): str(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}


def _labels(resource: Any) -> dict[str, str]:
    raw = resource.get("labels") if isinstance(resource, Mapping) else getattr(resource, "labels", None)
    return {str(key): str(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}


def _azure_resource_group(resource_id: str) -> str:
    parts = [part for part in resource_id.split("/") if part]
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("Azure target id is missing a resource group") from exc


def _azure_group_and_name(resource_id: str) -> tuple[str, str]:
    return _azure_resource_group(resource_id), resource_id.rstrip("/").rsplit("/", 1)[-1]


def _azure_disk_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    managed = getattr(item, "managed_disk", None)
    managed_id = managed.get("id") if isinstance(managed, Mapping) else getattr(managed, "id", None)
    return {
        "lun": getattr(item, "lun", None),
        "name": getattr(item, "name", ""),
        "create_option": getattr(item, "create_option", "Attach"),
        "managed_disk": {"id": str(managed_id or "")},
    }


def _gcp_zone(resource_id: str) -> str:
    parts = [part for part in resource_id.split("/") if part]
    try:
        return parts[parts.index("zones") + 1]
    except (ValueError, IndexError):
        return ""
