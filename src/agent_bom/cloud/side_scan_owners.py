"""Which VM owns a side-scanned disk, read from the provider (read-only, best effort).

The graph keys a VM exactly as cloud inventory does, so the owner must be the
provider's own identifier: the Azure VM ARM id from the disk's ``managed_by``,
and the numeric GCE instance id behind the disk's ``users`` self-link. A lookup
that fails records no owner; packages then stay on the disk node instead of
being attached to a guessed VM.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)


def _field(resource: Any, key: str) -> Any:
    return resource.get(key) if isinstance(resource, Mapping) else getattr(resource, key, None)


def _leaf(value: str) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1]


def azure_disk_owner(disks_client: Any, resource_group: str, disk_name: str) -> tuple[str, str]:
    """``(vm ARM id, vm name)`` from ``Disk.managed_by``; empty when unattached or unreadable."""
    try:
        managed_by = str(_field(disks_client.get(resource_group, disk_name), "managed_by") or "").strip()
    except Exception as exc:  # noqa: BLE001 — owner is enrichment; the scan proceeds without it
        logger.debug("side-scan: Azure disk owner lookup failed: %s", sanitize_text(exc))
        return "", ""
    return (managed_by, _leaf(managed_by)) if managed_by else ("", "")


def _instance_parts(link: str) -> tuple[str, str, str]:
    parts = [part for part in link.split("/") if part]
    try:
        project = parts[parts.index("projects") + 1]
        zone = parts[parts.index("zones") + 1]
        name = parts[parts.index("instances") + 1]
    except (ValueError, IndexError):
        return "", "", ""
    return project, zone, name


def gcp_disk_owner(disks_client: Any, instances_client: Any, *, project: str, zone: str, disk_name: str) -> tuple[str, str]:
    """``(numeric instance id, instance name)`` of the first instance using the disk."""
    try:
        users = list(_field(disks_client.get(request={"project": project, "zone": zone, "disk": disk_name}), "users") or [])
        owner_project, owner_zone, name = _instance_parts(str(users[0])) if users else ("", "", "")
        if not name:
            return "", ""
        instance = instances_client.get(project=owner_project, zone=owner_zone, instance=name)
    except Exception as exc:  # noqa: BLE001 — owner is enrichment; the scan proceeds without it
        logger.debug("side-scan: GCE disk owner lookup failed: %s", sanitize_text(exc))
        return "", ""
    numeric = str(_field(instance, "id") or "").strip()
    return (numeric, name) if numeric else ("", "")
