"""Vast.ai cloud discovery — rented GPU instances.

Vast.ai is a GPU marketplace used for burst fine-tuning and model serving.
Discovery uses the Vast.ai REST API to enumerate rented instances.

Authentication: ``VASTAI_API_KEY`` environment variable or ``--vastai-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
from agent_bom.security import sanitize_text

from .collection_errors import inventory_list
from .gpu_api import bearer_json_get, collect_gpu_inventory, missing_api_key_warning
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://console.vast.ai/api/v0"
_API_TIMEOUT = 15


def _vast_get(path: str, api_key: str) -> dict | list:
    return bearer_json_get(_API_BASE, path, api_key, label="Vast.ai", timeout=_API_TIMEOUT)


def _instance_agent(inst: dict) -> Agent:
    """Build the agent for one rented Vast.ai GPU instance."""
    inst_id = str(inst.get("id", "unknown"))
    status = inst.get("actual_status", inst.get("status", "unknown"))
    image = inst.get("image_uuid", inst.get("image_id", ""))
    gpu_name = inst.get("gpu_name", "GPU")
    gpu_count = inst.get("num_gpus", 1)
    hostname = inst.get("hostname", inst_id)
    location = inst.get("geolocation", inst.get("location", "unknown"))
    label = inst.get("label", hostname)

    packages = []
    container_sbom = None
    if image:
        img_name = image.split(":")[0].replace("/", "-")
        img_version = image.split(":")[-1] if ":" in image else "latest"
        packages.append(
            Package(
                name=img_name,
                version=img_version,
                ecosystem="container-image",
                purl=build_package_purl(
                    ecosystem="container-image",
                    name=img_name,
                    version=img_version,
                ),
            )
        )
        try:
            from agent_bom.cloud.container_sbom import scan_container_image

            container_sbom = scan_container_image(image).to_dict()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Container SBOM scan skipped for %s: %s", image, sanitize_text(exc))

    server = MCPServer(
        name=f"vastai:{label}",
        transport=TransportType.UNKNOWN,
        packages=packages,
        tools=[MCPTool(name=label, description=f"Vast.ai {gpu_name}x{gpu_count} ({location})")],
    )

    return Agent(
        name=f"vastai:{label}",
        agent_type=AgentType.CUSTOM,
        config_path=f"vastai://instance/{inst_id}",
        source="vastai",
        version=status,
        mcp_servers=[server],
        metadata={
            "gpu_type": gpu_name,
            "gpu_count": gpu_count,
            "location": location,
            "image": image,
            "container_sbom": container_sbom,
            "cloud_origin": build_cloud_origin(
                provider="vastai",
                service="compute",
                resource_type="gpu-instance",
                resource_id=inst_id,
                resource_name=label,
                raw_identity={"id": inst_id, "gpu": gpu_name, "location": location},
            ),
        },
    )


def discover(
    api_key: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Vast.ai rented GPU instances.

    Args:
        api_key: Vast.ai API key. Falls back to ``VASTAI_API_KEY`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    resolved_key = api_key or os.environ.get("VASTAI_API_KEY", "")
    if not resolved_key:
        return [], [missing_api_key_warning("VASTAI_API_KEY", "--vastai-api-key")]

    agents, warnings = collect_gpu_inventory(
        "vastai",
        lambda: inventory_list(_vast_get("/instances/?owner=me", resolved_key), "instances"),
        _instance_agent,
    )

    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=("vastai:all",),
        permissions_used=("vastai:instances:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Vast.ai: discovered %d instance(s)", len(agents))
    return agents, warnings
