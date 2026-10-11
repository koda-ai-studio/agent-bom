"""Azure storage, compute, container and secret-store discovery for the inventory facade."""

from __future__ import annotations

import importlib
from typing import Any

from ..normalization import sanitize_discovery_warning
from ._base import _clean_tags, _record_failure, _resource_group_from_id, _vm_identity, _vm_user_assigned_identity_ids

_FACADE = "agent_bom.cloud.azure_inventory"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _discover_storage_accounts(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Storage Account in the subscription (read-only).

    Public-access posture is read from the account's
    ``allow_blob_public_access`` and network-rule default action — never from
    blob contents. Accounts become ``DATA_STORE``-signalling nodes so DSPM and
    exposure overlays apply.
    """
    try:
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        warnings.append("azure-mgmt-storage not installed. Skipping Storage Account inventory.")
        return []

    accounts: list[dict[str, Any]] = []
    try:
        client = StorageManagementClient(credential, subscription_id)
        for account in client.storage_accounts.list():
            name = str(getattr(account, "name", "") or "").strip()
            if not name:
                continue
            account_id = str(getattr(account, "id", "") or "")
            network_rules = getattr(account, "network_rule_set", None)
            default_action = str(getattr(network_rules, "default_action", "") or "").lower()
            allow_public = bool(getattr(account, "allow_blob_public_access", False))
            # Publicly accessible when blob public access is allowed AND the
            # network firewall default action is not "deny".
            publicly_accessible = allow_public and default_action != "deny"
            account_record: dict[str, Any] = {
                "name": name,
                "id": account_id,
                "location": str(getattr(account, "location", "") or ""),
                "resource_group": _resource_group_from_id(account_id),
                "kind": str(getattr(account, "kind", "") or ""),
                "publicly_accessible": publicly_accessible,
                "allow_blob_public_access": allow_public,
                "network_default_action": default_action,
                "tags": _clean_tags(getattr(account, "tags", None)),
                "subscription_id": subscription_id,
            }
            # Opt-in DSPM blob content sampling (parity with S3/GCS). Reads bounded
            # blob byte ranges through the Storage Blob data plane and attaches
            # redacted content_classification evidence so the crown-jewel overlay
            # promotes a content-confirmed sensitive account. Best-effort — a
            # sampling failure never sinks storage inventory.
            _seams()._classify_storage_account_blobs(credential, account_record, warnings=warnings)
            accounts.append(account_record)
    except Exception as exc:  # noqa: BLE001 — one failed Azure Storage Accounts list must not sink the scan
        _record_failure(exc, "Azure Storage Accounts", "Microsoft.Storage/storageAccounts/read", warnings, missing)
    return accounts


def _classify_storage_account_blobs(credential: Any, account_record: dict[str, Any], *, warnings: list[str]) -> None:
    """Attach redacted DSPM blob content_classification when sampling is enabled.

    Opt-in via ``AGENT_BOM_DSPM_AZURE_BLOB_SAMPLING``. Opens the Storage Blob data
    plane with the same read-only brokered credential and samples bounded byte
    ranges; only redacted type/count/location evidence is attached. Never raises.
    """
    try:
        from agent_bom.cloud.azure_blob_data_classifier import azure_blob_sampling_enabled, classify_azure_blob_account

        if not azure_blob_sampling_enabled():
            return
        from azure.storage.blob import BlobServiceClient

        name = str(account_record.get("name") or "")
        account_url = f"https://{name}.blob.core.windows.net"
        service = BlobServiceClient(account_url=account_url, credential=credential)
        try:
            account_record["content_classification"] = classify_azure_blob_account(service, account=name).to_dict()
        finally:
            try:
                service.close()
            except Exception:  # noqa: BLE001 — client close is best-effort
                pass
    except Exception as exc:  # noqa: BLE001 — sampling is optional and must not sink inventory
        warnings.append(
            f"Could not classify Azure Blob content for storage account {account_record.get('name')}: {sanitize_discovery_warning(exc)}"
        )


def _discover_vms(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate all VMs in the subscription (read-only, NOT tag-filtered)."""
    try:
        from azure.mgmt.compute import ComputeManagementClient
    except ImportError:
        warnings.append("azure-mgmt-compute not installed. Skipping VM inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        client = ComputeManagementClient(credential, subscription_id)
        for vm in client.virtual_machines.list_all():
            vm_id = str(getattr(vm, "id", "") or "")
            name = str(getattr(vm, "name", "") or "").strip()
            if not name:
                continue
            hardware = getattr(vm, "hardware_profile", None)
            vm_size = str(getattr(hardware, "vm_size", "") or "")
            instances.append(
                {
                    "instance_id": vm_id or name,
                    "name": name,
                    "instance_type": vm_size,
                    "location": str(getattr(vm, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vm_id),
                    "managed_identity": _vm_identity(vm),
                    "user_assigned_identity_ids": _vm_user_assigned_identity_ids(vm),
                    "tags": _clean_tags(getattr(vm, "tags", None)),
                    "subscription_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure virtual machines list must not sink the scan
        _record_failure(exc, "Azure virtual machines", "Microsoft.Compute/virtualMachines/read", warnings, missing)
    return instances


def _discover_aks_clusters(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate AKS (managed Kubernetes) clusters in the subscription (read-only).

    Captures control-plane metadata: Kubernetes version, the API-server FQDN
    (its public reachability is the exposure signal), whether the API server is
    private, and whether Kubernetes RBAC is enabled. Never reads workload or
    secret contents.
    """
    try:
        from azure.mgmt.containerservice import ContainerServiceClient
    except ImportError:
        warnings.append("azure-mgmt-containerservice not installed. Skipping AKS inventory.")
        return []

    clusters: list[dict[str, Any]] = []
    try:
        client = ContainerServiceClient(credential, subscription_id)
        for cluster in client.managed_clusters.list():
            cluster_id = str(getattr(cluster, "id", "") or "")
            name = str(getattr(cluster, "name", "") or "").strip()
            if not name:
                continue
            api_profile = getattr(cluster, "api_server_access_profile", None)
            private_cluster = bool(getattr(api_profile, "enable_private_cluster", False)) if api_profile else False
            fqdn = str(getattr(cluster, "fqdn", "") or "")
            clusters.append(
                {
                    "name": name,
                    "id": cluster_id,
                    "native_type": "Microsoft.ContainerService/managedClusters",
                    "location": str(getattr(cluster, "location", "") or ""),
                    "resource_group": _resource_group_from_id(cluster_id),
                    "tags": _clean_tags(getattr(cluster, "tags", None)),
                    "kubernetes_version": str(getattr(cluster, "kubernetes_version", "") or ""),
                    "api_server_fqdn": fqdn,
                    "private_cluster": private_cluster,
                    "rbac_enabled": bool(getattr(cluster, "enable_rbac", False)),
                    # A reachable API-server FQDN on a non-private cluster is internet-facing.
                    "internet_facing": bool(fqdn) and not private_cluster,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure AKS clusters list must not sink the scan
        _record_failure(exc, "Azure AKS clusters", "Microsoft.ContainerService/managedClusters/read", warnings, missing)
    return clusters


def _discover_managed_identities(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate user-assigned managed identities in the subscription (read-only).

    Each identity becomes a ``service_principal`` graph node carrying its
    principal id so the effective-permissions overlay can attach
    ``HAS_PERMISSION`` once role-assignment data is wired. Privilege defaults to
    ``unknown`` — inventory never guesses an inflated level.
    """
    try:
        from azure.mgmt.msi import ManagedServiceIdentityClient
    except ImportError:
        warnings.append("azure-mgmt-msi not installed. Skipping managed-identity inventory.")
        return []

    identities: list[dict[str, Any]] = []
    try:
        client = ManagedServiceIdentityClient(credential, subscription_id)
        for identity in client.user_assigned_identities.list_by_subscription():
            identity_id = str(getattr(identity, "id", "") or "")
            name = str(getattr(identity, "name", "") or "").strip()
            if not name:
                continue
            identities.append(
                {
                    "principal_type": "managed-identity",
                    "name": name,
                    "arn": identity_id or name,
                    "principal_id": str(getattr(identity, "principal_id", "") or ""),
                    "client_id": str(getattr(identity, "client_id", "") or ""),
                    "location": str(getattr(identity, "location", "") or ""),
                    "resource_group": _resource_group_from_id(identity_id),
                    "account_id": subscription_id,
                    "policies": [],
                    "trust_principals": [],
                    "privilege_level": "unknown",
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure managed identities list must not sink the scan
        _record_failure(exc, "Azure managed identities", "Microsoft.ManagedIdentity/userAssignedIdentities/read", warnings, missing)
    return identities


def _discover_key_vaults(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Key Vault in the subscription (read-only).

    Reads only control-plane metadata (URI, RBAC mode, public-network posture);
    never reads secret/key/certificate material.
    """
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
    except ImportError:
        warnings.append("azure-mgmt-keyvault not installed. Skipping Key Vault inventory.")
        return []

    vaults: list[dict[str, Any]] = []
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        for vault in client.vaults.list_by_subscription():
            vault_id = str(getattr(vault, "id", "") or "")
            name = str(getattr(vault, "name", "") or "").strip()
            if not name:
                continue
            props = getattr(vault, "properties", None)
            vaults.append(
                {
                    "name": name,
                    "id": vault_id,
                    "location": str(getattr(vault, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vault_id),
                    "tags": _clean_tags(getattr(vault, "tags", None)),
                    "uri": str(getattr(props, "vault_uri", "") or "") if props else "",
                    "rbac_authorization": bool(getattr(props, "enable_rbac_authorization", False)) if props else False,
                    "public_network_access": str(getattr(props, "public_network_access", "") or "") if props else "",
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Key Vaults list must not sink the scan
        _record_failure(exc, "Azure Key Vaults", "Microsoft.KeyVault/vaults/read", warnings, missing)
    return vaults


def _discover_container_registries(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Container Registry in the subscription (read-only)."""
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    except ImportError:
        warnings.append("azure-mgmt-containerregistry not installed. Skipping Container Registry inventory.")
        return []

    registries: list[dict[str, Any]] = []
    try:
        client = ContainerRegistryManagementClient(credential, subscription_id)
        for registry in client.registries.list():
            registry_id = str(getattr(registry, "id", "") or "")
            name = str(getattr(registry, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(registry, "sku", None)
            registries.append(
                {
                    "name": name,
                    "id": registry_id,
                    "location": str(getattr(registry, "location", "") or ""),
                    "resource_group": _resource_group_from_id(registry_id),
                    "tags": _clean_tags(getattr(registry, "tags", None)),
                    "login_server": str(getattr(registry, "login_server", "") or ""),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "admin_user_enabled": bool(getattr(registry, "admin_user_enabled", False)),
                    "public_network_access": str(getattr(registry, "public_network_access", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Container Registries list must not sink the scan
        _record_failure(exc, "Azure Container Registries", "Microsoft.ContainerRegistry/registries/read", warnings, missing)
    return registries


def _discover_managed_disks(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Managed Disk in the subscription (read-only).

    Control-plane metadata only (size, encryption type, public-network posture);
    never reads disk contents. Disks hold data at rest, so they signal a data store.
    """
    try:
        from azure.mgmt.compute import ComputeManagementClient
    except ImportError:
        warnings.append("azure-mgmt-compute not installed. Skipping Managed Disk inventory.")
        return []

    disks: list[dict[str, Any]] = []
    try:
        client = ComputeManagementClient(credential, subscription_id)
        for disk in client.disks.list():
            disk_id = str(getattr(disk, "id", "") or "")
            name = str(getattr(disk, "name", "") or "").strip()
            if not name:
                continue
            encryption = getattr(disk, "encryption", None)
            disks.append(
                {
                    "name": name,
                    "id": disk_id,
                    "native_type": "Microsoft.Compute/disks",
                    "location": str(getattr(disk, "location", "") or ""),
                    "resource_group": _resource_group_from_id(disk_id),
                    "tags": _clean_tags(getattr(disk, "tags", None)),
                    "disk_size_gb": getattr(disk, "disk_size_gb", None),
                    "encryption_type": str(getattr(encryption, "type", "") or "") if encryption else "",
                    "public_network_access": str(getattr(disk, "public_network_access", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Managed Disks list must not sink the scan
        _record_failure(exc, "Azure Managed Disks", "Microsoft.Compute/disks/read", warnings, missing)
    return disks


def _discover_app_services(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every App Service site (Web Apps + Function Apps) read-only.

    ``web_apps.list()`` returns both; ``kind`` (contains ``functionapp``)
    distinguishes them. Control-plane metadata only — the public host name (the
    exposure signal), HTTPS-only, and public-network posture — never app code or
    app-setting/secret values.
    """
    try:
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError:
        warnings.append("azure-mgmt-web not installed. Skipping App Service inventory.")
        return []

    sites: list[dict[str, Any]] = []
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        for site in client.web_apps.list():
            site_id = str(getattr(site, "id", "") or "")
            name = str(getattr(site, "name", "") or "").strip()
            if not name:
                continue
            kind = str(getattr(site, "kind", "") or "")
            default_host_name = str(getattr(site, "default_host_name", "") or "")
            enabled = bool(getattr(site, "enabled", True))
            sites.append(
                {
                    "name": name,
                    "id": site_id,
                    "native_type": "Microsoft.Web/sites",
                    "location": str(getattr(site, "location", "") or ""),
                    "resource_group": _resource_group_from_id(site_id),
                    "tags": _clean_tags(getattr(site, "tags", None)),
                    "kind": kind,
                    "is_function_app": "functionapp" in kind.lower(),
                    "default_host_name": default_host_name,
                    "https_only": bool(getattr(site, "https_only", False)),
                    "public_network_access": str(getattr(site, "public_network_access", "") or ""),
                    "internet_facing": bool(default_host_name) and enabled,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure App Services list must not sink the scan
        _record_failure(exc, "Azure App Services", "Microsoft.Web/sites/read", warnings, missing)
    return sites
