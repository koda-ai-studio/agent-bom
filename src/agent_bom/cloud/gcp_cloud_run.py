"""Cloud Run service conversion: one agent per service, one server per container image."""

from __future__ import annotations

from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .gcp_errors import gcp_text, text_attr
from .normalization import build_cloud_origin, build_cloud_principal, build_cloud_scope, build_package_purl, parse_container_image_package


def _image_server(name: str, image: str) -> MCPServer:
    parts = parse_container_image_package(image)
    packages = (
        [
            Package(
                name=parts[0],
                version=parts[1],
                ecosystem="container-image",
                purl=build_package_purl(ecosystem="container-image", name=parts[0], version=parts[1]),
            )
        ]
        if parts
        else []
    )
    return MCPServer(name=name, command="docker", args=["run", image], transport=TransportType.STDIO, packages=packages)


def _container_servers(svc_name: str, containers: Any) -> tuple[list[MCPServer], list[str]]:
    servers: list[MCPServer] = []
    images: list[str] = []
    for index, container in enumerate(containers):
        image = gcp_text(getattr(container, "image", ""), "")
        if not image:
            continue
        container_name = text_attr(container, "name") or f"container-{index}"
        servers.append(_image_server(f"cloud-run:{svc_name}" if not servers else f"cloud-run:{svc_name}/{container_name}", image))
        images.append(image)
    return servers, images


def cloud_run_agent(service: Any, project_id: str, region: str) -> Agent | None:
    """Convert one Cloud Run service, or ``None`` when it runs no container image.

    Agent identity is type + name + config path, so per-container agents of
    one service would collide on the service resource name.
    """
    svc_resource = gcp_text(service.name, "")
    svc_name = svc_resource.split("/")[-1] if svc_resource else "unknown"
    template = service.template
    if not template or not template.containers:
        return None
    servers, images = _container_servers(svc_name, template.containers)
    if not servers:
        return None
    service_account = text_attr(template, "service_account")
    resource_id = svc_resource or f"gcp://{svc_name}"
    agent = Agent(
        name=f"cloud-run:{svc_name}",
        agent_type=AgentType.CUSTOM,
        config_path=resource_id,
        source="gcp-cloud-run",
        mcp_servers=servers,
        metadata={
            "gcp_project": project_id,
            "region": region,
            "image": images[0],
            "images": images,
            "cloud_origin": build_cloud_origin(
                provider="gcp",
                service="cloud-run",
                resource_type="service",
                resource_id=resource_id,
                resource_name=svc_name,
                location=region,
                project_id=project_id,
                raw_identity={"name": svc_resource, "image": images[0]},
            ),
        },
    )
    cloud_scope = build_cloud_scope(
        provider="gcp",
        service="cloud-run",
        resource_type="service",
        scope_type="project",
        scope_id=project_id,
        scope_name=project_id,
        location=region,
        source_fields=["name", "template.service_account"],
    )
    if cloud_scope:
        agent.metadata["cloud_scope"] = cloud_scope
    cloud_principal = build_cloud_principal(
        provider="gcp",
        service="cloud-run",
        resource_type="service",
        principal_type="service-account",
        principal_id=service_account or None,
        principal_name=service_account or None,
        source_field="template.service_account",
        raw_identity={"service_account": service_account},
    )
    if cloud_principal:
        agent.metadata["cloud_principal"] = cloud_principal
    return agent
