"""Per-record Azure inventory conversion shared by the discovery passes."""

from __future__ import annotations

from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .azure_errors import azure_text
from .normalization import build_cloud_origin, build_cloud_principal, build_cloud_scope, build_cloud_timestamps


def _extract_azure_resource_group(resource_id: str) -> str:
    """Extract Azure resource group name from a resource ID."""
    if not resource_id:
        return ""
    rg_parts = resource_id.split("/resourceGroups/")
    if len(rg_parts) < 2:
        return ""
    return rg_parts[1].split("/")[0]


def _build_azure_principal(
    *,
    service: str,
    resource_type: str,
    identity: Any,
) -> dict[str, Any] | None:
    """Normalize Azure workload identity metadata when present."""
    if not identity:
        return None
    identity_type = getattr(identity, "type", "") or ""
    principal_id = getattr(identity, "principal_id", "") or ""
    tenant_id = getattr(identity, "tenant_id", "") or ""
    user_assigned = getattr(identity, "user_assigned_identities", None) or {}
    principal_name = ""
    if not principal_id and user_assigned:
        first_identity = next(iter(user_assigned.keys()), "")
        principal_id = first_identity
        principal_name = first_identity
    normalized_type = (
        {
            "SystemAssigned": "system-assigned-managed-identity",
            "UserAssigned": "user-assigned-managed-identity",
            "SystemAssigned, UserAssigned": "mixed-managed-identity",
        }.get(identity_type)
        or identity_type.lower().replace("_", "-").replace(" ", "-")
        or "managed-identity"
    )
    return build_cloud_principal(
        provider="azure",
        service=service,
        resource_type=resource_type,
        principal_type=normalized_type,
        principal_id=principal_id or None,
        principal_name=principal_name or None,
        tenant_id=tenant_id or None,
        source_field="identity",
        raw_identity={
            "type": identity_type,
            "principal_id": principal_id,
            "tenant_id": tenant_id,
        },
    )


def _container_app_servers(template: Any) -> tuple[list[MCPServer], list[dict[str, str]]]:
    containers = getattr(template, "containers", []) or []
    if not isinstance(containers, list):
        raise TypeError("Invalid Container App template")
    servers: list[MCPServer] = []
    images: list[dict[str, str]] = []
    for container in containers:
        image = azure_text(getattr(container, "image", ""), "")
        if not image:
            continue
        container_name = azure_text(getattr(container, "name", ""), image)
        servers.append(MCPServer(name=f"container:{container_name}", command="docker", args=["run", image], transport=TransportType.STDIO))
        images.append({"name": container_name, "image": image})
    return servers, images


def _attach_resource_context(agent: Agent, resource: Any, *, service: str, resource_type: str, subscription_id: str, rg_name: str) -> None:
    """Resource-group scope, system timestamps and managed identity, when present."""
    cloud_scope = build_cloud_scope(
        provider="azure",
        service=service,
        resource_type=resource_type,
        scope_type="resource-group",
        scope_id=rg_name,
        scope_name=rg_name or None,
        parent_scope_type="subscription",
        parent_scope_id=subscription_id,
        location=getattr(resource, "location", None),
        source_fields=["id", "location"],
    )
    if cloud_scope:
        agent.metadata["cloud_scope"] = cloud_scope
    system_data = getattr(resource, "system_data", None)
    cloud_timestamps = build_cloud_timestamps(
        provider="azure",
        service=service,
        resource_type=resource_type,
        created_at=getattr(system_data, "created_at", None) if system_data else None,
        updated_at=getattr(system_data, "last_modified_at", None) if system_data else None,
        created_source="system_data.created_at",
        updated_source="system_data.last_modified_at",
    )
    if cloud_timestamps:
        agent.metadata["cloud_timestamps"] = cloud_timestamps
    cloud_principal = _build_azure_principal(service=service, resource_type=resource_type, identity=getattr(resource, "identity", None))
    if cloud_principal:
        agent.metadata["cloud_principal"] = cloud_principal


def _container_app_agent(app: Any, subscription_id: str, resource_group: str | None) -> Agent | None:
    """One agent per Container App, one server per container image.

    Agent identity is type + name + config path, so per-container agents of
    one app would collide on the app's resource id.
    """
    app_name = azure_text(app.name, "unknown")
    app_id = azure_text(app.id, "")
    template = getattr(app, "template", None)
    if not template:
        return None
    servers, images = _container_app_servers(template)
    if not servers:
        return None
    resource_id = app_id or f"azure://{app_name}"
    agent = Agent(
        name=f"azure-container-app:{app_name}",
        agent_type=AgentType.CUSTOM,
        config_path=resource_id,
        source="azure-container-apps",
        mcp_servers=servers,
        metadata={
            "containers": images,
            "cloud_origin": build_cloud_origin(
                provider="azure",
                service="container-apps",
                resource_type="container-app",
                resource_id=resource_id,
                resource_name=app_name,
                subscription_id=subscription_id,
                raw_identity={"id": app_id, "name": app_name},
            ),
        },
    )
    rg_name = resource_group or _extract_azure_resource_group(app_id)
    _attach_resource_context(
        agent, app, service="container-apps", resource_type="container-app", subscription_id=subscription_id, rg_name=rg_name
    )
    return agent
