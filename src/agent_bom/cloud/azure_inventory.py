"""Azure general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.azure` (which discovers *AI* runtimes: Container
Apps, AI Foundry agents, Azure OpenAI deployments, Functions, ML endpoints),
this module enumerates the general Azure estate so that a resource with **no**
CIS finding, IaC target, or discovered AI runtime still becomes a first-class
graph node. That feeds the CNAPP exposure overlay, the CIEM effective-
permissions overlay, and the DSPM tiers, which were previously starved of
inventory input.

Three resource classes are enumerated subscription-wide (NOT filtered to
findings):

1. **Storage Accounts**       → emitted as ``DATA_STORE``-signalling
   ``CLOUD_RESOURCE`` so the DSPM / ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **VMs + Network Security Groups** → emitted as ``CLOUD_RESOURCE``.
3. **Managed Identities / Service Principals** → emitted as identity principals
   with a ``HAS_PERMISSION``-ready structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_AZURE_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_CLOUD_INVENTORY``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Authentication is **token / credential only** — no passwords — via
``azure-identity`` (``DefaultAzureCredential``: env service-principal token,
managed identity, Azure CLI token, workload-identity). Only ``list`` / ``get``
ARM APIs are called — no write APIs, no object-content reads, no credential
exfiltration. SDK absence or missing credentials degrades to an empty inventory
plus a clear status, never a crash.

Requires ``azure-identity`` and ``azure-mgmt-*``. Install with::

    pip install 'agent-bom[azure]'
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .aws_inventory import dedupe_missing_permissions
from .azure_inv._base import (  # noqa: F401 - facade re-export
    _AZURE_COMPUTE_PERMISSIONS,
    _AZURE_DATA_PERMISSIONS,
    _AZURE_IDENTITY_PERMISSIONS,
    _AZURE_NETWORK_PERMISSIONS,
    _AZURE_STORAGE_PERMISSIONS,
    _COLLECTED_HEAD_KEYS,
    _COLLECTED_TAIL_KEYS,
    _INTERNET_SOURCES,
    _clean_tags,
    _derive_default_subscription,
    _empty_inventory,
    _public_ip_ref_value,
    _record_failure,
    _resource_group_from_id,
    _safe_int,
    _vm_identity,
    _vm_user_assigned_identity_ids,
    _vnet_id_from_subnet_id,
)
from .azure_inv.compute_storage import (  # noqa: F401 - facade re-export
    _classify_storage_account_blobs,
    _discover_aks_clusters,
    _discover_app_services,
    _discover_container_registries,
    _discover_key_vaults,
    _discover_managed_disks,
    _discover_managed_identities,
    _discover_storage_accounts,
    _discover_vms,
)
from .azure_inv.data import (  # noqa: F401 - facade re-export
    _append_db_servers,
    _discover_databases,
    _discover_event_hubs,
    _discover_redis_caches,
    _discover_service_bus,
)
from .azure_inv.edge import (  # noqa: F401 - facade re-export
    _discover_api_management,
    _discover_application_gateways,
    _discover_azure_firewalls,
    _discover_front_doors,
    _discover_load_balancers,
)
from .azure_inv.identity import (  # noqa: F401 - facade re-export
    _ENTRA_MEMBER_TYPE,
    _collect_entra_groups,
    _collect_entra_service_principals,
    _collect_entra_users,
    _discover_authorization,
    _discover_management_groups,
    _discover_role_assignments,
    _entra_group_members,
    _subscription_ids_from_mg_tree,
)
from .azure_inv.network import (  # noqa: F401 - facade re-export
    _discover_ip_addresses,
    _discover_nat_gateways,
    _discover_network_interfaces,
    _discover_nsgs,
    _discover_private_endpoints,
    _discover_public_ips,
    _discover_route_tables,
    _discover_subnets,
    _discover_virtual_networks,
    _normalize_network_interface,
    _normalize_nsg,
    _nsg_internet_exposure,
    _route_table_has_internet_route,
    _rule_port_range,
    _rule_sources,
)
from .azure_rbac_evidence import normalize_azure_rbac_inventory
from .normalization import sanitize_discovery_warning
from .side_scan_target_records import azure_managed_disk_targets

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Mirrors the other AGENT_BOM_* feature gates.
INVENTORY_ENV_FLAG = "AGENT_BOM_AZURE_INVENTORY"

_TRUTHY = {"1", "true", "yes", "on"}


def inventory_enabled() -> bool:
    """Return whether estate-wide Azure inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_AZURE_INVENTORY``
    to a truthy value (``1`` / ``true`` / ``yes`` / ``on``).
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def discover_inventory(
    subscription_id: str | None = None,
    *,
    credential: Any = None,
    include_storage: bool = True,
    include_compute: bool = True,
    include_identity: bool = True,
    include_data: bool = True,
    include_network: bool = True,
    include_hierarchy: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Enumerate the general Azure estate (storage, VMs + NSGs, identities).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``           — the feature flag is off and ``force`` was not set.
    - ``"sdk_missing"``        — azure-identity / azure-mgmt is not installed.
    - ``"no_subscription"``    — no subscription id resolved.
    - ``"no_credentials"``     — no Azure credential resolved.
    - ``"ok"``                 — enumeration ran (possibly with per-service warnings).

    Never raises: SDK absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.

    Authentication is token/credential only (no passwords). When ``credential``
    is not supplied, ``DefaultAzureCredential`` is used, which acquires
    short-lived tokens from env service principals, managed identity, the Azure
    CLI, or workload identity.
    """
    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    empty = _empty_inventory(resolved_sub)
    if not force and not inventory_enabled():
        return empty

    warnings: list[str] = []
    credential, resolved_sub, early_exit = _resolve_session(empty, credential, resolved_sub, warnings)
    if early_exit is not None:
        return early_exit

    discovery_tasks = _inventory_discovery_tasks(
        include_storage=include_storage,
        include_compute=include_compute,
        include_identity=include_identity,
        include_data=include_data,
        include_network=include_network,
    )
    collected, missing = _run_discovery_tasks(discovery_tasks, credential, resolved_sub, warnings)
    management_groups, service_principals, entra_groups, entra_users, entra_ran = _discover_tenant_scope(
        credential, include_hierarchy=include_hierarchy, include_identity=include_identity, warnings=warnings, missing=missing
    )
    envelope = _discovery_envelope(
        resolved_sub,
        include_storage=include_storage,
        include_compute=include_compute,
        include_identity=include_identity,
        include_data=include_data,
        include_network=include_network,
        include_hierarchy=include_hierarchy,
        entra_ran=entra_ran,
    )
    return _assemble_inventory(
        resolved_sub,
        collected,
        include_identity=include_identity,
        management_groups=management_groups,
        service_principals=service_principals,
        entra_groups=entra_groups,
        entra_users=entra_users,
        envelope=envelope,
        warnings=warnings,
        missing=missing,
    )


def _resolve_session(
    empty: dict[str, Any], credential: Any, resolved_sub: str, warnings: list[str]
) -> tuple[Any, str, dict[str, Any] | None]:
    """Credential + subscription setup stage: ``(credential, subscription, early_exit_payload)``."""
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
    except ImportError:
        hint = "azure-identity is required for Azure inventory. Install with: pip install 'agent-bom[azure]'"
        return credential, resolved_sub, {**empty, "status": "sdk_missing", "warnings": [hint]}

    if credential is None:
        try:
            credential = DefaultAzureCredential()
        except Exception as exc:  # noqa: BLE001 — credential chain errors must not crash a scan
            return credential, resolved_sub, {**empty, "status": "no_credentials", "warnings": [sanitize_discovery_warning(exc)]}

    # Auto-derive the subscription from the signed-in credential (e.g. ``az
    # login``) when one was not supplied, so the common single-subscription case
    # connects with zero extra configuration. Multi-subscription tenants still
    # fan out via the management-group path or an explicit AZURE_SUBSCRIPTION_ID.
    if not resolved_sub:
        resolved_sub, derive_note = _derive_default_subscription(credential)
        if derive_note:
            warnings.append(derive_note)
        if not resolved_sub:
            hint = "No Azure subscription found. Run `az login`, set AZURE_SUBSCRIPTION_ID, or pass subscription_id."
            return credential, resolved_sub, {**empty, "status": "no_subscription", "warnings": [hint]}
        empty["subscription_id"] = resolved_sub
        empty["account_id"] = resolved_sub
    return credential, resolved_sub, None


def _inventory_discovery_tasks(
    *, include_storage: bool, include_compute: bool, include_identity: bool, include_data: bool, include_network: bool
) -> list[tuple[str, Any]]:
    """Ordered ``(result_key, discoverer)`` pairs for the per-subscription pool.

    Discoverers are resolved as module globals at call time so each stays
    individually patchable.
    """
    discovery_tasks: list[tuple[str, Any]] = []
    if include_storage:
        discovery_tasks.append(("storage_accounts", _discover_storage_accounts))
    if include_compute:
        discovery_tasks.append(("instances", _discover_vms))
        discovery_tasks.append(("container_clusters", _discover_aks_clusters))
        discovery_tasks.append(("managed_disks", _discover_managed_disks))
        discovery_tasks.append(("app_services", _discover_app_services))
        discovery_tasks.append(("security_groups", _discover_nsgs))
    if include_identity:
        discovery_tasks.append(("managed_identities", _discover_managed_identities))
        discovery_tasks.append(("authorization", _discover_authorization))
    if include_data:
        discovery_tasks.append(("key_vaults", _discover_key_vaults))
        discovery_tasks.append(("container_registries", _discover_container_registries))
        discovery_tasks.append(("databases", _discover_databases))
        discovery_tasks.append(("event_hubs", _discover_event_hubs))
        discovery_tasks.append(("service_bus_namespaces", _discover_service_bus))
        discovery_tasks.append(("redis_caches", _discover_redis_caches))
    if include_network:
        discovery_tasks.append(("virtual_networks", _discover_virtual_networks))
        discovery_tasks.append(("subnets", _discover_subnets))
        discovery_tasks.append(("public_ips", _discover_public_ips))
        discovery_tasks.append(("ip_addresses", _discover_ip_addresses))
        discovery_tasks.append(("network_interfaces", _discover_network_interfaces))
        discovery_tasks.append(("load_balancers", _discover_load_balancers))
        discovery_tasks.append(("application_gateways", _discover_application_gateways))
        discovery_tasks.append(("front_doors", _discover_front_doors))
        discovery_tasks.append(("azure_firewalls", _discover_azure_firewalls))
        discovery_tasks.append(("nat_gateways", _discover_nat_gateways))
        discovery_tasks.append(("route_tables", _discover_route_tables))
        discovery_tasks.append(("private_endpoints", _discover_private_endpoints))
        discovery_tasks.append(("api_management", _discover_api_management))
    return discovery_tasks


def _run_discovery_tasks(
    discovery_tasks: list[tuple[str, Any]], credential: Any, resolved_sub: str, warnings: list[str]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Run the per-subscription discoverers concurrently; return ``(collected, missing)``.

    The ARM list calls are independent and IO-bound, so a thread pool collapses
    the previously-sequential sum-of-latencies sweep to roughly the slowest
    single call. Each task gets its own warnings list (thread-safe) that is
    merged back into ``warnings`` in deterministic task order.
    """
    collected: dict[str, Any] = {}
    task_warnings: dict[str, list[str]] = {key: [] for key, _ in discovery_tasks}
    # Parallel per-task accumulator so one discoverer's missing-permission entries
    # never race another's. Merged back in deterministic task order, then deduped.
    task_missing: dict[str, list[dict[str, str]]] = {key: [] for key, _ in discovery_tasks}
    missing: list[dict[str, str]] = []
    if discovery_tasks:
        with ThreadPoolExecutor(max_workers=min(8, len(discovery_tasks))) as executor:
            future_to_key = {
                executor.submit(fn, credential, resolved_sub, warnings=task_warnings[key], missing=task_missing[key]): key
                for key, fn in discovery_tasks
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    collected[key] = future.result()
                except Exception as exc:  # noqa: BLE001 — one service failing must not sink the rest
                    collected[key] = []
                    # Translate the abort into the same actionable guidance a
                    # discoverer-local failure would have produced, so a crash at
                    # the future boundary is never a silent empty result.
                    _record_failure(exc, key.replace("_", " "), f"Microsoft.*/{key}/read", task_warnings[key], task_missing[key])
    for key, _ in discovery_tasks:
        warnings.extend(task_warnings[key])
        missing.extend(task_missing[key])
    return collected, missing


def _discover_tenant_scope(
    credential: Any, *, include_hierarchy: bool, include_identity: bool, warnings: list[str], missing: list[dict[str, str]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Collect hierarchy and opt-in directory principals once per tenant."""
    # Management groups are tenant-scoped (above the subscription), so they are
    # discovered with a single call rather than the per-subscription thread pool.
    management_groups: list[dict[str, Any]] = []
    if include_hierarchy:
        management_groups, mg_warnings = _discover_management_groups(credential)
        warnings.extend(mg_warnings)

    # Entra (Azure AD) directory read — service principals + groups + memberships.
    # Tenant-scoped and uses a Microsoft Graph token (not the ARM credential), so
    # it runs once outside the per-subscription pool. Opt-in + degrades to empty:
    # the ARM scan above is complete regardless of whether this grant is present.
    service_principals: list[dict[str, Any]] = []
    entra_groups: list[dict[str, Any]] = []
    entra_users: list[dict[str, Any]] = []
    entra_ran = False
    if include_identity:
        entra_missing: list[dict[str, str]] = []
        service_principals, entra_groups = _discover_entra_directory(warnings=warnings, missing=entra_missing, users=entra_users)
        missing.extend(entra_missing)
        entra_ran = bool(service_principals or entra_groups or entra_users or entra_missing)
    return management_groups, service_principals, entra_groups, entra_users, entra_ran


def _discovery_envelope(
    resolved_sub: str,
    *,
    include_storage: bool,
    include_compute: bool,
    include_identity: bool,
    include_data: bool,
    include_network: bool,
    include_hierarchy: bool,
    entra_ran: bool,
) -> DiscoveryEnvelope:
    """Build the per-run discovery envelope from the read actions actually exercised."""
    permissions_used: list[str] = []
    if include_storage:
        permissions_used.extend(_AZURE_STORAGE_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_AZURE_COMPUTE_PERMISSIONS)
    if include_identity:
        permissions_used.extend(_AZURE_IDENTITY_PERMISSIONS)
    if include_data:
        permissions_used.extend(_AZURE_DATA_PERMISSIONS)
    if include_network:
        permissions_used.extend(_AZURE_NETWORK_PERMISSIONS)
    if include_hierarchy:
        permissions_used.append("Microsoft.Management/managementGroups/read")
    if entra_ran:
        # Additional read-only Microsoft Graph grant beyond the ARM Reader role.
        from agent_bom.identity.entra_nhi import ENTRA_READ_PERMISSIONS

        permissions_used.extend(ENTRA_READ_PERMISSIONS)

    return DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"azure:subscription/{resolved_sub}",),
        permissions_used=tuple(sorted(set(permissions_used))),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )


def _assemble_inventory(
    resolved_sub: str,
    collected: dict[str, Any],
    *,
    include_identity: bool,
    management_groups: list[dict[str, Any]],
    service_principals: list[dict[str, Any]],
    entra_groups: list[dict[str, Any]],
    entra_users: list[dict[str, Any]],
    envelope: DiscoveryEnvelope,
    warnings: list[str],
    missing: list[dict[str, str]],
) -> dict[str, Any]:
    """Result-assembly stage: shape the collected service lists into the ``"ok"`` payload."""
    authorization = collected.get("authorization", {})
    if not isinstance(authorization, dict):
        authorization = {}
    authorization_fields = {
        "role_assignments": authorization.get("role_assignments", []),
        "role_definitions": authorization.get("role_definitions", []),
        "deny_assignments": authorization.get("deny_assignments", []),
        "authorization_sources": authorization.get("authorization_sources", []),
        "authorization_observed_at": authorization.get("authorization_observed_at"),
    }
    authorization_payload = {
        "status": "ok" if include_identity else "disabled",
        "subscription_id": resolved_sub,
        "account_id": resolved_sub,
        **authorization_fields,
        "entra_groups": entra_groups,
    }
    authorization_evidence = normalize_azure_rbac_inventory(authorization_payload).to_dict()
    managed_disks = collected.get("managed_disks", [])

    return {
        "provider": "azure",
        "status": "ok",
        "subscription_id": resolved_sub,
        "account_id": resolved_sub,
        "region": "",
        **{key: collected.get(key, []) for key in _COLLECTED_HEAD_KEYS},
        **authorization_fields,
        "authorization_evidence": authorization_evidence,
        "service_principals": service_principals,
        "entra_users": entra_users,
        "entra_groups": entra_groups,
        **{key: collected.get(key, []) for key in _COLLECTED_TAIL_KEYS},
        "managed_disks": managed_disks,
        "side_scan_targets": azure_managed_disk_targets(managed_disks, subscription_id=resolved_sub),
        "app_services": collected.get("app_services", []),
        "management_groups": management_groups,
        "warnings": warnings,
        "missing_permissions": dedupe_missing_permissions(missing),
        "discovery_envelope": envelope.to_dict(),
    }


# Multi-subscription fan-out is opt-in (enumerating every subscription in a
# tenant is heavier than a single-sub scan). Mirrors the AWS Organizations
# multi-account enumeration: discover the subscription set, then inventory each.
ALL_SUBSCRIPTIONS_ENV_FLAG = "AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS"
# Defensive cap so a tenant with thousands of subscriptions can't run unbounded
# without an operator opting into a larger budget.
_MAX_SUBSCRIPTIONS = int(os.environ.get("AGENT_BOM_AZURE_MAX_SUBSCRIPTIONS", "500") or "500")


def all_subscriptions_enabled() -> bool:
    """Whether to fan a single scan across every subscription in the tenant."""
    return os.environ.get(ALL_SUBSCRIPTIONS_ENV_FLAG, "").strip().lower() in _TRUTHY


def enumerate_subscription_ids(credential: Any, *, allow_ambient_fallback: bool = True) -> tuple[list[str], list[str]]:
    """Resolve every subscription id to fan a single scan across (read-only).

    The single source of truth for the multi-subscription boundary set: discover
    the management-group hierarchy, extract every subscription id from it, and
    fall back to the configured ``AZURE_SUBSCRIPTION_ID`` when the tenant root is
    not visible (e.g. the credential lacks Management Group Reader). Returns
    ``(subscription_ids, warnings)``; never raises. Shared by both the inventory
    fan-out and the CIS-benchmark fan-out so the boundary set stays identical.
    """
    warnings: list[str] = []
    try:
        management_groups, mg_warnings = _discover_management_groups(credential)
        warnings.extend(mg_warnings)
    except Exception as exc:  # noqa: BLE001 — MG enumeration failure must degrade, not crash
        management_groups = []
        warnings.append(sanitize_discovery_warning(exc))

    sub_ids = _subscription_ids_from_mg_tree(management_groups)
    if not sub_ids and allow_ambient_fallback:
        # No tenant-root visibility — fall back to the single configured sub.
        single = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
        if single:
            sub_ids = [single]
    return sub_ids, warnings


def discover_all_subscription_inventories(
    credential: Any = None, *, force: bool = False, allow_ambient_fallback: bool = True
) -> list[dict[str, Any]]:
    """Inventory the scopes discovered through the credential's hierarchy access.

    Returns per-scope payloads, bounded by the configured collection cap.
    CLI callers may fall back to the ambient scope when discovery is unavailable;
    saved connections disable that fallback. Permission gaps do not establish
    full organization coverage. Read-only; never raises.
    """
    if not force and not inventory_enabled():
        return []
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
    except ImportError:
        return []
    if credential is None:
        try:
            credential = DefaultAzureCredential()
        except Exception:  # noqa: BLE001
            return []

    sub_ids, _warnings = (
        enumerate_subscription_ids(credential)
        if allow_ambient_fallback
        else enumerate_subscription_ids(credential, allow_ambient_fallback=False)
    )

    payloads: list[dict[str, Any]] = []
    for sub_id in sub_ids[:_MAX_SUBSCRIPTIONS]:
        payloads.append(discover_inventory(subscription_id=sub_id, credential=credential, force=True))
    if len(sub_ids) > _MAX_SUBSCRIPTIONS:
        logger.warning(
            "Azure multi-subscription scan capped at %d of %d subscriptions (set AGENT_BOM_AZURE_MAX_SUBSCRIPTIONS to raise).",
            _MAX_SUBSCRIPTIONS,
            len(sub_ids),
        )
    return payloads


# Microsoft Graph directory-read fan-out caps. A hostile/huge tenant must not be
# able to make group-membership expansion run unbounded.
_ENTRA_MAX_GROUPS_EXPANDED = int(os.environ.get("AGENT_BOM_ENTRA_MAX_GROUPS", "500") or "500")


def entra_directory_enabled() -> bool:
    """Whether the opt-in Microsoft Graph directory-read path is enabled.

    Reuses the existing Entra NHI discovery gate (``AGENT_BOM_ENTRA_DISCOVERY``)
    so service-principal + Entra-group discovery shares one opt-in switch. This
    needs Microsoft Graph ``Directory.Read.All`` — a read-only grant the ARM
    ``Reader`` role does NOT include — so it stays default OFF and additive.
    """
    from agent_bom.identity import entra_nhi

    return entra_nhi._is_truthy(os.environ.get(entra_nhi._DISCOVERY_FLAG_ENV))


def _discover_entra_directory(
    *,
    client: Any = None,
    force: bool = False,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    users: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Discover Entra service principals + groups (with members) — opt-in, read-only.

    Returns ``(service_principals, entra_groups)``. A service principal that holds
    a dangerous role is invisible to RBAC analysis unless it is a node, and a role
    granted to a group only reaches its members once membership is known — this
    closes both gaps.

    Permission posture: this calls Microsoft Graph (``servicePrincipals`` /
    ``groups`` / ``groups/{id}/members``) which requires ``Directory.Read.All``,
    NOT covered by the ARM ``Reader`` role. It is therefore gated behind the same
    ``AGENT_BOM_ENTRA_DISCOVERY`` flag (token via ``AGENT_BOM_ENTRA_TOKEN``) as
    the Entra NHI path and is purely additive. When the gate is off, the token is
    missing, or the Graph permission is denied, it warns and returns empty so the
    rest of the ARM scan proceeds unaffected.
    """
    client = _entra_directory_client(client, force=force, warnings=warnings)
    if client is None:
        return [], []
    service_principals = _collect_entra_service_principals(client, warnings=warnings, missing=missing)
    entra_groups = _collect_entra_groups(client, warnings=warnings, missing=missing)
    if users is not None:
        users.extend(_collect_entra_users(client, warnings=warnings, missing=missing))
    warnings.extend(getattr(client, "coverage_warnings", []))
    return service_principals, entra_groups


def _entra_directory_client(client: Any, *, force: bool, warnings: list[str]) -> Any:
    """Gate + Graph client setup stage; ``None`` means skip directory discovery."""
    from agent_bom.identity import entra_nhi

    gate_on = force or client is not None or entra_directory_enabled()
    if not gate_on:
        # Opt-in feature, default OFF: stay silent so a normal ARM-only scan is not
        # spammed with a note every run. The grant requirement is documented; a
        # warning is reserved for "enabled but the token/permission is missing".
        return None

    if client is None:
        token = (os.environ.get(entra_nhi._TOKEN_ENV) or "").strip()
        if not token:
            warnings.append(f"Entra directory discovery enabled but {entra_nhi._TOKEN_ENV} is not set; skipping (ARM scan continues).")
            return None
        try:
            client = entra_nhi.EntraClient(token)
        except Exception as exc:  # noqa: BLE001 — client init failure must not sink the scan
            warnings.append(f"Could not initialise the Microsoft Graph client for directory discovery: {sanitize_discovery_warning(exc)}")
            return None
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


__all__ = [
    "ALL_SUBSCRIPTIONS_ENV_FLAG",
    "INVENTORY_ENV_FLAG",
    "all_subscriptions_enabled",
    "discover_all_subscription_inventories",
    "discover_inventory",
    "enumerate_subscription_ids",
    "inventory_enabled",
]
