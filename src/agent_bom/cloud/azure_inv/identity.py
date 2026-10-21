"""Azure authorization, Entra directory and management-group discovery for the inventory facade."""

from __future__ import annotations

import importlib
from typing import Any

from ..azure_authorization_collector import collect_azure_authorization
from ..normalization import sanitize_discovery_warning
from ._base import _record_failure

_FACADE = "agent_bom.cloud.azure_inventory"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


def _subscription_ids_from_mg_tree(management_groups: list[dict[str, Any]]) -> list[str]:
    """Extract every subscription id from the management-group hierarchy tree."""
    sub_ids: list[str] = []
    for group in management_groups:
        for child in group.get("children", []) or []:
            if "subscriptions" in str(child.get("type", "")).lower():
                sid = str(child.get("name", "") or "").strip()
                if sid and sid not in sub_ids:
                    sub_ids.append(sid)
    return sub_ids


def _discover_authorization(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> dict[str, Any]:
    """Collect decision-capable Azure RBAC authorization evidence read-only."""
    return collect_azure_authorization(
        credential,
        subscription_id,
        warnings=warnings,
        missing=missing,
    )


def _discover_role_assignments(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning assignments from full RBAC evidence.

    Each assignment links a principal (managed identity / service principal /
    user / group) to a scope (subscription, resource group, or a specific
    resource) via a role. The graph turns these into ``HAS_PERMISSION`` edges so
    effective-access / privilege-escalation analysis can run on real RBAC rather
    than guessed privilege. Role-definition ids are resolved to names once and
    cached. Requires ``Microsoft.Authorization/roleAssignments/read`` +
    ``roleDefinitions/read`` (both included in Reader).
    """
    return _seams()._discover_authorization(credential, subscription_id, warnings=warnings, missing=missing)["role_assignments"]


# Map a Microsoft Graph ``@odata.type`` to the canonical principal type the graph
# builder understands, so a group member resolves to the right node entity.
_ENTRA_MEMBER_TYPE: dict[str, str] = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.serviceprincipal": "service-principal",
    "#microsoft.graph.group": "group",
}


def _collect_entra_service_principals(client: Any, *, warnings: list[str], missing: list[dict[str, str]] | None) -> list[dict[str, Any]]:
    """List Entra service principals as principal records (failure degrades to a warning)."""
    service_principals: list[dict[str, Any]] = []
    try:
        for sp in client.list_service_principals() or []:
            if not isinstance(sp, dict):
                continue
            sp_id = str(sp.get("id") or "").strip()
            if not sp_id:
                continue
            service_principals.append(
                {
                    "principal_type": "service-principal",
                    "name": str(sp.get("displayName") or sp_id),
                    "arn": sp_id,
                    "principal_id": sp_id,
                    "app_id": str(sp.get("appId") or ""),
                    "service_principal_type": str(sp.get("servicePrincipalType") or ""),
                    "policies": [],
                    "trust_principals": [],
                    "privilege_level": "unknown",
                }
            )
    except Exception as exc:  # noqa: BLE001 — Graph SP listing failure degrades to a warning
        _record_failure(exc, "Entra service principals", "Directory.Read.All", warnings, missing)
    return service_principals


def _collect_entra_users(client: Any, *, warnings: list[str], missing: list[dict[str, str]] | None) -> list[dict[str, Any]]:
    """Keep native object IDs and an explicit user kind for RBAC/group joins."""
    users: dict[str, dict[str, Any]] = {}
    try:
        for user in client.list_users() or []:
            if not isinstance(user, dict) or not str(user.get("id") or "").strip():
                continue
            user_id = str(user["id"]).strip()
            users[user_id] = {
                "principal_type": "user",
                "principal_id": user_id,
                "arn": user_id,
                "name": str(user.get("displayName") or user_id),
                "account_enabled": user.get("accountEnabled") if isinstance(user.get("accountEnabled"), bool) else None,
                "user_type": str(user.get("userType") or ""),
                "policies": [],
                "privilege_level": "unknown",
            }
    except Exception as exc:  # noqa: BLE001 — a denied user read must preserve other inventory
        _record_failure(exc, "Entra users", "Directory.Read.All", warnings, missing)
    return list(users.values())


def _collect_entra_groups(client: Any, *, warnings: list[str], missing: list[dict[str, str]] | None) -> list[dict[str, Any]]:
    """List Entra groups, expanding members for the first ``_ENTRA_MAX_GROUPS_EXPANDED``."""
    try:
        raw_groups = list(client.list_groups() or [])
    except Exception as exc:  # noqa: BLE001 — Graph group listing failure degrades to a warning
        _record_failure(exc, "Entra groups", "Directory.Read.All", warnings, missing)
        raw_groups = []

    entra_groups: list[dict[str, Any]] = []
    expanded = 0
    for group in raw_groups:
        if not isinstance(group, dict):
            continue
        group_id = str(group.get("id") or "").strip()
        if not group_id:
            continue
        members: list[dict[str, str]] = []
        if expanded < _seams()._ENTRA_MAX_GROUPS_EXPANDED:
            expanded += 1
            members = _entra_group_members(client, group_id, warnings=warnings)
        entra_groups.append(
            {
                "principal_type": "group",
                "name": str(group.get("displayName") or group_id),
                "arn": group_id,
                "principal_id": group_id,
                "members": members,
                "policies": [],
                "privilege_level": "unknown",
            }
        )
    return entra_groups


def _entra_group_members(client: Any, group_id: str, *, warnings: list[str]) -> list[dict[str, str]]:
    """Read one group's members; a failure keeps members read so far and warns."""
    members: list[dict[str, str]] = []
    try:
        for member in client.list_group_members(group_id) or []:
            if not isinstance(member, dict):
                continue
            member_id = str(member.get("id") or "").strip()
            if not member_id:
                continue
            odata = str(member.get("@odata.type") or "").strip().lower()
            members.append(
                {
                    "id": member_id,
                    "name": str(member.get("displayName") or member_id),
                    "type": _ENTRA_MEMBER_TYPE.get(odata, "user"),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one group's member read must not sink the rest
        warnings.append(f"Entra group-member read skipped for {group_id}: {sanitize_discovery_warning(exc)}")
    return members


def _discover_management_groups(credential: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Enumerate the tenant's management-group hierarchy (read-only, tenant-scoped).

    Management groups sit above subscriptions and organize them into a tree.
    Each entry carries its direct children (nested management groups and
    subscriptions) so the graph can build the CONTAINS hierarchy across
    subscriptions. Requires the Management Group Reader role at the tenant root;
    absent that, this degrades to an empty list plus a warning.
    """
    try:
        # azure-mgmt-managementgroups 2.0.0 renamed the top-level client
        # ManagementGroupsAPI -> ManagementGroupsMgmtClient. Prefer the new
        # name and fall back to the old one so both ends of the >=1.0 pin work.
        try:
            from azure.mgmt.managementgroups import (
                ManagementGroupsMgmtClient as _MgmtGroupsClient,
            )
        except ImportError:
            from azure.mgmt.managementgroups import (  # type: ignore[attr-defined,no-redef]
                ManagementGroupsAPI as _MgmtGroupsClient,
            )
    except ImportError:
        return [], ["azure-mgmt-managementgroups not installed. Skipping management-group hierarchy."]

    groups: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        client = _MgmtGroupsClient(credential)
        for mg in client.management_groups.list():
            name = str(getattr(mg, "name", "") or "").strip()
            if not name:
                continue
            children: list[dict[str, Any]] = []
            try:
                detail = client.management_groups.get(group_id=name, expand="children", recurse=False)
                for child in getattr(detail, "children", None) or []:
                    children.append(
                        {
                            "id": str(getattr(child, "id", "") or ""),
                            "name": str(getattr(child, "name", "") or ""),
                            # ".../managementGroups" (nested group) or "/subscriptions" (a subscription)
                            "type": str(getattr(child, "type", "") or ""),
                            "display_name": str(getattr(child, "display_name", "") or ""),
                        }
                    )
            except Exception as exc:  # noqa: BLE001 — child expansion is best-effort
                warnings.append(f"Could not expand management group {name}: {sanitize_discovery_warning(exc)}")
            groups.append(
                {
                    "id": str(getattr(mg, "id", "") or ""),
                    "name": name,
                    "display_name": str(getattr(mg, "display_name", "") or ""),
                    "children": children,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure management groups: {sanitize_discovery_warning(exc)}")
    return groups, warnings
