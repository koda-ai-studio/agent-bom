"""Opt-in Azure Managed Disk and GCP Persistent Disk lifecycle adapters.

The adapters accept already-authenticated provider SDK clients.  They never
load credentials, transfer block bytes, or mount filesystems themselves.  All
temporary resources use deterministic names and the ownership tags from the v1
side-scan execution contract; durable state is updated after each mutation so
cleanup can resume after a worker restart.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

from .side_scan_cleanup import (
    SideScanLifecycleTimeoutError as SideScanLifecycleTimeoutError,
)
from .side_scan_cleanup import (
    SideScanOwnershipError as SideScanOwnershipError,
)
from .side_scan_cleanup import (
    SideScanPermissionDeniedError as SideScanPermissionDeniedError,
)
from .side_scan_cleanup import (
    _is_not_found,
    _PersistedLifecycleAdapter,
)
from .side_scan_cleanup import (
    sanitized_provider_error as sanitized_provider_error,
)
from .side_scan_lifecycle import SideScanExecutionRecord, SideScanStateStore
from .side_scan_owners import azure_disk_owner, gcp_disk_owner
from .side_scan_provider_ids import _azure_disk_dict, _azure_group_and_name, _azure_resource_group, _gcp_zone, _labels, _tags
from .side_scan_targets import CloudSideScanTarget


class AzureManagedDiskLifecycleAdapter(_PersistedLifecycleAdapter):
    """Azure Compute SDK adapter for snapshot/temp-disk/collector lifecycle."""

    provider = "azure"

    def __init__(
        self,
        *,
        snapshots_client: Any,
        disks_client: Any,
        virtual_machines_client: Any,
        execution: SideScanExecutionRecord | None,
        state_store: SideScanStateStore,
        collector_resource_group: str,
        collector_vm_name: str,
        collector_lun: int = 63,
        max_wait_attempts: int = 60,
        wait_interval_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            execution=execution,
            state_store=state_store,
            max_wait_attempts=max_wait_attempts,
            wait_interval_seconds=wait_interval_seconds,
            sleep=sleep,
        )
        if collector_vm_name != self.execution.collector_id or not collector_resource_group.strip() or not collector_vm_name.strip():
            raise ValueError("Azure collector resource group and VM name are required")
        if collector_lun < 0 or collector_lun > 63:
            raise ValueError("Azure collector LUN must be between 0 and 63")
        self._snapshots = snapshots_client
        self._disks = disks_client
        self._vms = virtual_machines_client
        self._collector_resource_group = collector_resource_group
        self._collector_vm_name = collector_vm_name
        self._collector_lun = collector_lun

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        self._validate_target(target)
        self._ensure_running("snapshot")
        resource_group = _azure_resource_group(target.target_id)
        self.owner_instance_id, self.owner_instance_name = azure_disk_owner(self._disks, *_azure_group_and_name(target.target_id))
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "snapshot")
        try:
            existing = self._azure_get(self._snapshots, resource_group, name)
            if existing is not None:
                self._assert_owned(_tags(existing))
                resource_id = _resource_id(existing)
            else:
                self._begin_mutation()
                operation = self._snapshots.begin_create_or_update(
                    resource_group,
                    name,
                    {
                        "location": target.location,
                        "tags": self.execution.cleanup_ownership.required_tags(),
                        "creation_data": {"create_option": "Copy", "source_resource_id": target.target_id},
                    },
                )
                resource_id = _resource_id(self._wait(operation))
            self._register("snapshot", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("temp_disk")
        resource_group = _azure_resource_group(target.target_id)
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")
        try:
            existing = self._azure_get(self._disks, resource_group, name)
            if existing is not None:
                self._assert_owned(_tags(existing))
                resource_id = _resource_id(existing)
            else:
                self._begin_mutation()
                operation = self._disks.begin_create_or_update(
                    resource_group,
                    name,
                    {
                        "location": target.location,
                        "tags": self.execution.cleanup_ownership.required_tags(),
                        "creation_data": {"create_option": "Copy", "source_resource_id": snapshot_id},
                    },
                )
                resource_id = _resource_id(self._wait(operation))
            self._register("scan_disk", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("attached")
        if collector_id != self.execution.collector_id or collector_id != self._collector_vm_name:
            raise ValueError("collector is outside the persisted execution scope")
        try:
            vm = self._vms.get(self._collector_resource_group, self._collector_vm_name)
            current = [_azure_disk_dict(item) for item in getattr(getattr(vm, "storage_profile", None), "data_disks", []) or []]
            attached_ids = {str((item.get("managed_disk") or {}).get("id") or "") for item in current}
            if scan_disk_id not in attached_ids:
                if any(int(item.get("lun", -1)) == self._collector_lun for item in current):
                    raise ValueError("configured Azure collector LUN is already occupied")
                current.append(
                    {
                        "lun": self._collector_lun,
                        "name": _resource_name(self.execution.cleanup_ownership.owner_id, "disk"),
                        "create_option": "Attach",
                        "managed_disk": {"id": scan_disk_id},
                    }
                )
                self._begin_mutation()
                self._wait(
                    self._vms.begin_update(
                        self._collector_resource_group,
                        self._collector_vm_name,
                        {"storage_profile": {"data_disks": current}},
                    )
                )
            self._register("attachment", f"{collector_id}|{scan_disk_id}")
            return f"/dev/disk/azure/scsi1/lun{self._collector_lun}"
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        self._validate_target(target)
        if collector_id != self.execution.collector_id:
            raise ValueError("collector is outside the persisted execution scope")
        if not self._verify_owned_resource(target, scan_disk_id, "scan_disk"):
            return
        vm = self._vms.get(self._collector_resource_group, self._collector_vm_name)
        current = [_azure_disk_dict(item) for item in getattr(getattr(vm, "storage_profile", None), "data_disks", []) or []]
        retained = [item for item in current if str((item.get("managed_disk") or {}).get("id") or "") != scan_disk_id]
        if len(retained) == len(current):
            return
        self._wait(
            self._vms.begin_update(
                self._collector_resource_group,
                self._collector_vm_name,
                {"storage_profile": {"data_disks": retained}},
            )
        )

    def _verify_owned_resource(self, target: CloudSideScanTarget, resource_id: str, kind: str) -> bool:
        self._require_registered(target, resource_id, kind)
        resource_type = "disks" if kind == "scan_disk" else "snapshots"
        prefix = f"/subscriptions/{self.execution.account_id}/resourcegroups/".lower()
        if not resource_id.lower().startswith(prefix) or f"/providers/microsoft.compute/{resource_type}/" not in resource_id.lower():
            raise SideScanOwnershipError("Azure cleanup resource is outside the execution account")
        group, name = _azure_group_and_name(resource_id)
        client = self._disks if kind == "scan_disk" else self._snapshots
        resource = self._azure_get(client, group, name)
        if resource is None:
            return False
        if _resource_id(resource).lower() != resource_id.lower():
            raise SideScanOwnershipError("Azure cleanup resource identity changed")
        self._assert_owned(_tags(resource))
        return True

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        if not self._verify_owned_resource(target, scan_disk_id, "scan_disk"):
            return
        resource_group, name = _azure_group_and_name(scan_disk_id)
        try:
            self._wait(self._disks.begin_delete(resource_group, name))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        if not self._verify_owned_resource(target, snapshot_id, "snapshot"):
            return
        resource_group, name = _azure_group_and_name(snapshot_id)
        try:
            self._wait(self._snapshots.begin_delete(resource_group, name))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    @staticmethod
    def _azure_get(client: Any, resource_group: str, name: str) -> Any | None:
        try:
            return client.get(resource_group, name)
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def _assert_owned(self, tags: Mapping[str, str]) -> None:
        if not self.execution.cleanup_ownership.owns(tags):
            raise SideScanOwnershipError("deterministic Azure resource name is not owned by this execution")


class GcpPersistentDiskLifecycleAdapter(_PersistedLifecycleAdapter):
    """Google Compute Engine SDK adapter for snapshot/temp-disk lifecycle."""

    provider = "gcp"

    def __init__(
        self,
        *,
        snapshots_client: Any,
        disks_client: Any,
        instances_client: Any,
        execution: SideScanExecutionRecord | None,
        state_store: SideScanStateStore,
        project_id: str,
        collector_zone: str,
        collector_instance: str,
        max_wait_attempts: int = 60,
        wait_interval_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            execution=execution,
            state_store=state_store,
            max_wait_attempts=max_wait_attempts,
            wait_interval_seconds=wait_interval_seconds,
            sleep=sleep,
        )
        if execution is not None and execution.account_id != project_id:
            raise ValueError("GCP project does not match persisted execution scope")
        if (
            collector_instance != self.execution.collector_id
            or not project_id.strip()
            or not collector_zone.strip()
            or not collector_instance.strip()
        ):
            raise ValueError("GCP project, collector zone, and collector instance are required")
        self._snapshots = snapshots_client
        self._disks = disks_client
        self._instances = instances_client
        self._project = project_id
        self._collector_zone = collector_zone
        self._collector_instance = collector_instance
        self._device_name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")

    def create_snapshot(self, target: CloudSideScanTarget) -> str:
        self._validate_target(target)
        self._ensure_running("snapshot")
        if target.target_type == "image":
            # The temp disk is built straight from the image; nothing to snapshot.
            return ""
        self.owner_instance_id, self.owner_instance_name = gcp_disk_owner(
            self._disks,
            self._instances,
            project=self._project,
            zone=_gcp_zone(target.target_id) or target.location,
            disk_name=target.target_id.rstrip("/").rsplit("/", 1)[-1],
        )
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "snapshot")
        try:
            existing = self._gcp_get(self._snapshots, {"project": self._project, "snapshot": name})
            if existing is not None:
                self._assert_owned(_labels(existing))
                resource_id = _resource_id(existing)
            else:
                self._begin_mutation()
                operation = self._snapshots.insert(
                    request={
                        "project": self._project,
                        "snapshot_resource": {
                            "name": name,
                            "source_disk": target.target_id,
                            "labels": self.execution.cleanup_ownership.required_tags(),
                        },
                    }
                )
                self._wait(operation)
                created = self._gcp_get(self._snapshots, {"project": self._project, "snapshot": name})
                if created is None:
                    raise RuntimeError("created GCP snapshot could not be read back")
                resource_id = _resource_id(created)
            self._register("snapshot", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def create_scan_disk(self, target: CloudSideScanTarget, snapshot_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("temp_disk")
        name = _resource_name(self.execution.cleanup_ownership.owner_id, "disk")
        try:
            existing = self._gcp_get(
                self._disks,
                {"project": self._project, "zone": target.location, "disk": name},
            )
            if existing is not None:
                self._assert_owned(_labels(existing))
                resource_id = _resource_id(existing)
            else:
                self._begin_mutation()
                operation = self._disks.insert(
                    request={
                        "project": self._project,
                        "zone": target.location,
                        "disk_resource": {
                            "name": name,
                            **({"source_image": target.target_id} if target.target_type == "image" else {"source_snapshot": snapshot_id}),
                            "labels": self.execution.cleanup_ownership.required_tags(),
                        },
                    }
                )
                self._wait(operation)
                created = self._gcp_get(
                    self._disks,
                    {"project": self._project, "zone": target.location, "disk": name},
                )
                if created is None:
                    raise RuntimeError("created GCP disk could not be read back")
                resource_id = _resource_id(created)
            self._register("scan_disk", resource_id)
            return resource_id
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def attach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> str:
        self._validate_target(target)
        self._ensure_running("attached")
        if collector_id != self.execution.collector_id or collector_id != self._collector_instance:
            raise ValueError("collector is outside the persisted execution scope")
        try:
            self._begin_mutation()
            self._wait(
                self._instances.attach_disk(
                    request={
                        "project": self._project,
                        "zone": self._collector_zone,
                        "instance": self._collector_instance,
                        "attached_disk_resource": {
                            "source": scan_disk_id,
                            "device_name": self._device_name,
                            "mode": "READ_ONLY",
                            "auto_delete": False,
                        },
                    }
                )
            )
            self._register("attachment", f"{collector_id}|{scan_disk_id}")
            return f"/dev/disk/by-id/google-{self._device_name}"
        except Exception as exc:  # noqa: BLE001
            self._raise_provider_error(exc)
            raise AssertionError("unreachable")

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        self._validate_target(target)
        if collector_id != self.execution.collector_id:
            raise ValueError("collector is outside the persisted execution scope")
        if not self._verify_owned_resource(target, scan_disk_id, "scan_disk"):
            return
        current = self._instances.get(
            request={"project": self._project, "zone": self._collector_zone, "instance": self._collector_instance}
        )
        attached = current.get("disks", []) if isinstance(current, Mapping) else getattr(current, "disks", [])
        matches = [
            disk
            for disk in attached
            if (disk.get("device_name") if isinstance(disk, Mapping) else getattr(disk, "device_name", "")) == self._device_name
        ]
        if not matches:
            return
        sources = [disk.get("source", "") if isinstance(disk, Mapping) else getattr(disk, "source", "") for disk in matches]
        if len(sources) != 1 or _gcp_resource_path(sources[0]) != _gcp_resource_path(scan_disk_id):
            raise SideScanOwnershipError("GCP collector attachment no longer refers to the recorded disk")
        try:
            self._wait(
                self._instances.detach_disk(
                    request={
                        "project": self._project,
                        "zone": self._collector_zone,
                        "instance": self._collector_instance,
                        "device_name": self._device_name,
                    }
                )
            )
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def _verify_owned_resource(self, target: CloudSideScanTarget, resource_id: str, kind: str) -> bool:
        self._require_registered(target, resource_id, kind)
        canonical = _gcp_resource_path(resource_id)
        zone = _gcp_zone(resource_id)
        expected = (
            f"projects/{self._project}/zones/{self._collector_zone}/disks/"
            if kind == "scan_disk"
            else f"projects/{self._project}/global/snapshots/"
        )
        if not canonical.startswith(expected) or "/" in canonical[len(expected) :]:
            raise SideScanOwnershipError("GCP cleanup resource is outside the execution project or zone")
        name = canonical.rsplit("/", 1)[-1]
        request = {"project": self._project, **({"zone": zone, "disk": name} if kind == "scan_disk" else {"snapshot": name})}
        resource = self._gcp_get(self._disks if kind == "scan_disk" else self._snapshots, request)
        if resource is None:
            return False
        if _gcp_resource_path(_resource_id(resource)) != canonical:
            raise SideScanOwnershipError("GCP cleanup resource identity changed")
        self._assert_owned(_labels(resource))
        return True

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        if not self._verify_owned_resource(target, scan_disk_id, "scan_disk"):
            return
        name = scan_disk_id.rsplit("/", 1)[-1]
        zone = _gcp_zone(scan_disk_id) or target.location
        try:
            self._wait(self._disks.delete(request={"project": self._project, "zone": zone, "disk": name}))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        if not self._verify_owned_resource(target, snapshot_id, "snapshot"):
            return
        name = snapshot_id.rsplit("/", 1)[-1]
        try:
            self._wait(self._snapshots.delete(request={"project": self._project, "snapshot": name}))
        except Exception as exc:
            if not _is_not_found(exc):
                raise

    @staticmethod
    def _gcp_get(client: Any, request: dict[str, str]) -> Any | None:
        try:
            return client.get(request=request)
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def _assert_owned(self, labels: Mapping[str, str]) -> None:
        if not self.execution.cleanup_ownership.owns(labels):
            raise SideScanOwnershipError("deterministic GCP resource name is not owned by this execution")


def _resource_name(owner_id: str, suffix: str) -> str:
    return f"abom-{owner_id}-{suffix}"[:63]


def _resource_id(resource: Any) -> str:
    if isinstance(resource, Mapping):
        value = resource.get("self_link") or resource.get("selfLink") or resource.get("id") or resource.get("name")
    else:
        value = getattr(resource, "self_link", None) or getattr(resource, "id", None) or getattr(resource, "name", None)
    result = str(value or "").strip()
    if not result:
        raise RuntimeError("provider operation returned no resource id")
    return result


def _gcp_resource_path(value: str) -> str:
    return value.removeprefix("https://compute.googleapis.com/compute/v1/").removeprefix("https://www.googleapis.com/compute/v1/")
