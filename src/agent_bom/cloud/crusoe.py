"""Crusoe Energy cloud discovery — sustainable GPU instances.

Crusoe Energy is a GPU cloud focused on AI workloads powered by stranded
natural gas.  Discovery uses the Crusoe Cloud REST API.

Authentication: ``CRUSOE_API_KEY`` environment variable or ``--crusoe-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom import http_client  # noqa: F401  # module attribute kept as the documented patch point
from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .collection_errors import inventory_list
from .gpu_api import bearer_json_get, collect_gpu_inventory, missing_api_key_warning
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://api.crusoecloud.com/v1alpha5"
_API_TIMEOUT = 15


def _crusoe_get(path: str, api_key: str) -> dict | list:
    return bearer_json_get(_API_BASE, path, api_key, label="Crusoe", timeout=_API_TIMEOUT, extra_headers={"Accept": "application/json"})


def _vm_agent(vm: dict) -> Agent:
    """Build the agent for one Crusoe GPU VM."""
    vm_id = str(vm.get("id", "unknown"))
    vm_name = vm.get("name", vm_id)
    status = vm.get("state", vm.get("status", "unknown"))
    location = vm.get("location", vm.get("datacenter", "unknown"))

    vm_type = vm.get("type", vm.get("vm_type", ""))
    gpu_count_raw = vm.get("gpus", vm.get("gpu_count", 0))
    gpu_count = int(gpu_count_raw) if str(gpu_count_raw).isdigit() else 1
    # Crusoe uses "h100.80gb.sxm" style type names
    gpu_label = vm_type.split(".")[0].upper() if vm_type else "GPU"

    packages = [
        Package(
            name=vm_type or "crusoe-gpu-vm",
            version=status,
            ecosystem="crusoe-cloud",
            purl=build_package_purl(
                ecosystem="crusoe-cloud",
                name=vm_type or "crusoe-gpu-vm",
                version=status,
            ),
        )
    ]

    server = MCPServer(
        name=f"crusoe:{vm_name}",
        transport=TransportType.UNKNOWN,
        packages=packages,
        tools=[MCPTool(name=vm_name, description=f"Crusoe {gpu_label}x{gpu_count} ({location})")],
    )

    return Agent(
        name=f"crusoe:{vm_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"crusoe://vm/{vm_id}",
        source="crusoe",
        version=status,
        mcp_servers=[server],
        metadata={
            "gpu_type": gpu_label,
            "gpu_count": gpu_count,
            "location": location,
            "vm_type": vm_type,
            "cloud_origin": build_cloud_origin(
                provider="crusoe",
                service="compute",
                resource_type="gpu-vm",
                resource_id=vm_id,
                resource_name=vm_name,
                raw_identity={"id": vm_id, "type": vm_type, "location": location},
            ),
        },
    )


def discover(
    api_key: str | None = None,
    project_id: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Crusoe Energy GPU instances.

    Args:
        api_key:    Crusoe API key. Falls back to ``CRUSOE_API_KEY`` env var.
        project_id: Crusoe project ID. Falls back to ``CRUSOE_PROJECT_ID`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    resolved_key = api_key or os.environ.get("CRUSOE_API_KEY", "")
    resolved_project = project_id or os.environ.get("CRUSOE_PROJECT_ID", "")

    if not resolved_key:
        return [], [missing_api_key_warning("CRUSOE_API_KEY", "--crusoe-api-key")]

    path = f"/projects/{resolved_project}/compute/vms" if resolved_project else "/compute/vms"
    agents, warnings = collect_gpu_inventory(
        "crusoe",
        lambda: inventory_list(_crusoe_get(path, resolved_key), "items", "vms"),
        _vm_agent,
    )

    scope = (f"crusoe:project/{resolved_project}",) if resolved_project else ("crusoe:all",)
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=scope,
        permissions_used=("crusoe:vms:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Crusoe: discovered %d VM(s)", len(agents))
    return agents, warnings
