"""Which side-scan targets may be machine images, per provider."""

from __future__ import annotations

from .side_scan import SideScanConfigError

AZURE_IMAGE_UNSUPPORTED = (
    "Azure managed image side-scan is not supported: this executor scans managed disks only. Creating a temp "
    "disk from a managed image (Microsoft.Compute/images) or an Azure Compute Gallery image version is not "
    "implemented or proven; scan the managed disk of a VM built from the image instead."
)


def resolve_target_type(provider: str, target_type: str) -> str:
    """The lifecycle target type for a ``disk`` or ``image`` request; refuses unsupported images."""
    if target_type not in {"disk", "image"}:
        raise SideScanConfigError("side-scan target_type must be 'disk' or 'image'")
    if target_type == "image":
        if provider == "azure":
            raise SideScanConfigError(AZURE_IMAGE_UNSUPPORTED)
        return "image"
    return "managed_disk" if provider == "azure" else "persistent_disk"
