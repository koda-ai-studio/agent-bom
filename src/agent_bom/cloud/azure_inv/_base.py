"""Shared Azure inventory permission catalogs, payload shape and resource-id helpers."""

from __future__ import annotations

from typing import Any

from ..aws_inventory import record_discovery_failure
from ..normalization import sanitize_discovery_warning

# Read-only ARM actions this scanner is allowed to exercise, by resource class.
# Kept here so the per-run discovery envelope `permissions_used` stays honest.
_AZURE_STORAGE_PERMISSIONS: tuple[str, ...] = ("Microsoft.Storage/storageAccounts/read",)


_AZURE_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/disks/read",
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.Web/sites/read",
    "Microsoft.Network/networkSecurityGroups/read",
)


_AZURE_IDENTITY_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.ManagedIdentity/userAssignedIdentities/read",
    "Microsoft.Authorization/denyAssignments/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
)


_AZURE_DATA_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.ContainerRegistry/registries/read",
    "Microsoft.DocumentDB/databaseAccounts/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.DBforPostgreSQL/flexibleServers/read",
    "Microsoft.DBforMySQL/flexibleServers/read",
    "Microsoft.EventHub/namespaces/read",
    "Microsoft.ServiceBus/namespaces/read",
    "Microsoft.Cache/redis/read",
)


_AZURE_NETWORK_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/frontDoors/read",
    "Microsoft.Network/azureFirewalls/read",
    "Microsoft.Network/natGateways/read",
    "Microsoft.Network/routeTables/read",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/privateEndpoints/read",
    "Microsoft.ApiManagement/service/read",
)


# Open-to-the-world source-address ranges that mark an NSG inbound rule as
# internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any", "::/0"}


def _record_failure(
    exc: BaseException, resource_type: str, permission: str, warnings: list[str], missing: list[dict[str, str]] | None
) -> None:
    """Record one failed Azure discovery call via the shared cross-cloud translator."""
    record_discovery_failure(exc=exc, resource_type=resource_type, permission=permission, cloud="azure", warnings=warnings, missing=missing)


def _derive_default_subscription(credential: Any) -> tuple[str, str]:
    """Best-effort ``(subscription_id, note)`` from the signed-in credential.

    Lists the subscriptions visible to the credential and returns the first
    enabled one, so a single-subscription ``az login`` needs no explicit
    ``AZURE_SUBSCRIPTION_ID``. Returns ``("", note)`` on any failure — read-only
    and never raises. When more than one subscription is visible, the note asks
    the operator to pin one so selection stays deterministic.
    """
    import json
    import urllib.request

    # Read-only ARM subscriptions list — the same endpoint the SDK clients call,
    # reached directly with the credential's own bearer token so no extra SDK
    # distribution is required just to resolve the subscription.
    try:
        token = credential.get_token("https://management.azure.com/.default").token
    except Exception as exc:  # noqa: BLE001 — token acquisition must not crash a scan
        return "", sanitize_discovery_warning(exc)
    request = urllib.request.Request(  # noqa: S310 — fixed https ARM endpoint, not user input
        "https://management.azure.com/subscriptions?api-version=2022-12-01",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310  # nosec B310 — fixed https ARM endpoint, not user input
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — listing failures degrade to a warning
        return "", sanitize_discovery_warning(exc)

    subs = [s for s in payload.get("value", []) if s.get("subscriptionId")]
    enabled = [s for s in subs if str(s.get("state", "Enabled")) == "Enabled"] or subs
    if not enabled:
        return "", "No Azure subscriptions visible to the signed-in credential."
    chosen = enabled[0]["subscriptionId"]
    note = ""
    if len(enabled) > 1:
        note = (
            f"AZURE_SUBSCRIPTION_ID not set; auto-selected subscription {chosen} "
            f"of {len(enabled)} visible. Set AZURE_SUBSCRIPTION_ID to pin one."
        )
    return str(chosen), note


# Service-list keys copied straight from the discovery pool into the payload,
# in payload order, on either side of the authorization / Entra block.
_COLLECTED_HEAD_KEYS = ("storage_accounts", "instances", "container_clusters", "security_groups", "managed_identities")


_COLLECTED_TAIL_KEYS = (
    "key_vaults",
    "container_registries",
    "databases",
    "virtual_networks",
    "subnets",
    "public_ips",
    "ip_addresses",
    "network_interfaces",
    "load_balancers",
    "application_gateways",
    "front_doors",
    "azure_firewalls",
    "nat_gateways",
    "route_tables",
    "private_endpoints",
    "api_management",
    "event_hubs",
    "service_bus_namespaces",
    "redis_caches",
)


def _empty_inventory(resolved_sub: str) -> dict[str, Any]:
    """Return the ``"disabled"`` payload skeleton that every early exit derives from."""
    return {
        "provider": "azure",
        "status": "disabled",
        "subscription_id": resolved_sub,
        "account_id": resolved_sub,
        "region": "",
        **{key: [] for key in _COLLECTED_HEAD_KEYS},
        "role_assignments": [],
        "role_definitions": [],
        "deny_assignments": [],
        "authorization_sources": [],
        "authorization_observed_at": None,
        "authorization_evidence": None,
        "service_principals": [],
        "entra_groups": [],
        **{key: [] for key in _COLLECTED_TAIL_KEYS},
        "managed_disks": [],
        "app_services": [],
        "management_groups": [],
        "warnings": [],
        "missing_permissions": [],
        "discovery_envelope": None,
    }


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _vm_identity(vm: Any) -> str:
    identity = getattr(vm, "identity", None)
    if identity is None:
        return ""
    return str(getattr(identity, "principal_id", "") or getattr(identity, "type", "") or "")


def _vm_user_assigned_identity_ids(vm: Any) -> list[str]:
    """ARM IDs of the user-assigned managed identities attached to a VM.

    The VM assumes each of these identities' permissions, so they drive the
    VM → managed-identity privilege edge in the graph. Returns the resource IDs
    only (the dict keys) — never any credential material.
    """
    identity = getattr(vm, "identity", None)
    if identity is None:
        return []
    user_assigned = getattr(identity, "user_assigned_identities", None)
    if not isinstance(user_assigned, dict):
        return []
    return [str(arm_id) for arm_id in user_assigned if arm_id]


def _vnet_id_from_subnet_id(subnet_id: str) -> str:
    """Derive the parent VNet ARM id from a subnet ARM id, else ''.

    A subnet id is ``.../virtualNetworks/<vnet>/subnets/<subnet>``; the VNet id is
    everything up to and including the ``virtualNetworks/<vnet>`` segment.
    """
    text = str(subnet_id or "")
    marker = "/subnets/"
    index = text.lower().find(marker)
    return text[:index] if index != -1 else ""


def _public_ip_ref_value(ref: Any) -> str:
    """Resolve a public-IP sub-resource reference to its address, else its ARM id.

    A NIC / firewall IP configuration usually carries only the public IP's ``id``
    in a list response; the actual address is preferred when present.
    """
    if ref is None:
        return ""
    return str(getattr(ref, "ip_address", "") or getattr(ref, "id", "") or "")


def _resource_group_from_id(resource_id: str) -> str:
    """Extract the resourceGroups segment from an ARM resource id, else ''."""
    parts = [p for p in str(resource_id or "").split("/") if p]
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _clean_tags(tags: Any) -> dict[str, str]:
    if not isinstance(tags, dict):
        return {}
    return {str(key): str(value) for key, value in tags.items() if key is not None}
