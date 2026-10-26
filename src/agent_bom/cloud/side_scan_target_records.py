"""Project inventoried Azure Managed Disks and GCP Persistent Disks into side-scan targets."""

from __future__ import annotations

from typing import Any

from .side_scan_targets import CloudSideScanTarget


def azure_managed_disk_targets(disks: list[dict[str, Any]], *, subscription_id: str) -> list[dict[str, Any]]:
    """Project Azure Managed Disks into side-scan target records."""

    targets: list[dict[str, Any]] = []
    for disk in disks:
        target_id = str(disk.get("id") or disk.get("name") or "").strip()
        name = str(disk.get("name") or target_id).strip()
        if not target_id or not name:
            continue
        size = disk.get("disk_size_gb")
        targets.append(
            CloudSideScanTarget(
                provider="azure",
                target_type="managed_disk",
                target_id=target_id,
                name=name,
                account_id=subscription_id,
                location=str(disk.get("location") or ""),
                size_gb=size if isinstance(size, int) else None,
                encryption=str(disk.get("encryption_type") or "unknown"),
            ).to_dict()
        )
    return targets


def gcp_persistent_disk_targets(disks: list[dict[str, Any]], *, project_id: str) -> list[dict[str, Any]]:
    """Project GCP Persistent Disks into side-scan target records."""

    targets: list[dict[str, Any]] = []
    for disk in disks:
        target_id = str(disk.get("id") or disk.get("name") or "").strip()
        name = str(disk.get("name") or target_id).strip()
        if not target_id or not name:
            continue
        size = disk.get("size_gb")
        encryption = "customer-managed" if disk.get("encrypted") else "provider-managed-or-unknown"
        targets.append(
            CloudSideScanTarget(
                provider="gcp",
                target_type="persistent_disk",
                target_id=target_id,
                name=name,
                account_id=project_id,
                location=str(disk.get("location") or ""),
                size_gb=size if isinstance(size, int) else None,
                encryption=encryption,
            ).to_dict()
        )
    return targets
