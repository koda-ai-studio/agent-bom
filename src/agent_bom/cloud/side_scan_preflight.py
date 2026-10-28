"""Pre-flight validation for the Azure/GCP side-scan executor.

Every refusal here happens before a lifecycle record is written: an unsupported
provider, the opt-in switch being off, incomplete scope, or a tenant-scoped
caller that supplied no authorized ``client_factory`` (ambient provider
credentials are reserved for the operator-run CLI, which opts in explicitly).
"""

from __future__ import annotations

from .side_scan import SideScanConfigError, SideScanDisabledError, is_sidescan_enabled
from .side_scan_images import resolve_target_type


def validate_provider_side_scan_request(
    *,
    provider: str,
    target_id: str,
    account_id: str,
    location: str,
    collector_id: str,
    target_type: str,
    collector_resource_group: str | None,
    has_client_factory: bool,
    allow_ambient: bool,
) -> str:
    """Fail closed on an unsupported, disabled, incomplete or unauthorized request before any state is written."""
    if provider not in {"azure", "gcp"}:
        raise SideScanConfigError("run_provider_side_scan handles only azure|gcp; use run_side_scan for AWS EBS")
    if not is_sidescan_enabled():
        raise SideScanDisabledError(
            "Disk side-scan is opt-in and currently OFF. Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role "
            "plus an in-account collector instance."
        )

    required = (
        ("--volume-id (target disk id)", target_id),
        ("--account-id (subscription/project)", account_id),
        ("--availability-zone (disk location/zone)", location),
        ("--collector-instance-id (in-account collector)", collector_id),
    )
    missing = [label for label, value in required if not str(value).strip()]
    if missing:
        raise SideScanConfigError(f"{provider} side-scan requires: {', '.join(missing)}")
    lifecycle_type = resolve_target_type(provider, target_type)
    if provider == "azure" and not str(collector_resource_group or "").strip():
        raise SideScanConfigError("Azure Managed Disk side-scan requires --collector-resource-group for the in-account collector VM")
    if not has_client_factory and not allow_ambient:
        raise SideScanConfigError(
            "Side-scan requires an authorized client_factory; ambient provider credentials are only available to the local CLI."
        )
    return lifecycle_type


__all__ = ["validate_provider_side_scan_request"]
