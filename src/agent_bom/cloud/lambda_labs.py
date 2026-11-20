"""Lambda Labs cloud discovery — GPU instances and fine-tuning jobs.

Lambda Labs is a GPU cloud used heavily for enterprise fine-tuning and
inference.  Discovery uses the Lambda Cloud REST API.

Authentication: ``LAMBDA_API_KEY`` environment variable or ``--lambda-api-key`` CLI flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .collection_errors import inventory_list
from .gpu_api import bearer_json_get, collect_gpu_inventory, missing_api_key_warning
from .normalization import build_cloud_origin, build_package_purl

logger = logging.getLogger(__name__)

_API_BASE = "https://cloud.lambdalabs.com/api/v1"
_API_TIMEOUT = 15

# Lambda GPU instance type families → normalised capability label
_GPU_FAMILIES: dict[str, str] = {
    "gpu_1x_h100_pcie": "H100-PCIe",
    "gpu_1x_h100_sxm4": "H100-SXM4",
    "gpu_8x_h100_80gb_sxm4": "H100x8-SXM4",
    "gpu_1x_a100": "A100",
    "gpu_8x_a100": "A100x8",
    "gpu_1x_a10": "A10",
    "gpu_4x_a10": "A10x4",
    "gpu_1x_rtx6000": "RTX6000",
    "gpu_1x_v100": "V100",
}


def _lambda_get(path: str, api_key: str) -> dict | list:
    return bearer_json_get(_API_BASE, path, api_key, label="Lambda Labs", timeout=_API_TIMEOUT)


def _instance_agent(inst: dict) -> Agent:
    """Build the agent for one Lambda Cloud GPU instance."""
    inst_id = inst.get("id", "unknown")
    inst_name = inst.get("name", inst_id)
    status = inst.get("status", "unknown")
    region = inst.get("region", {}).get("name", "unknown")
    itype = inst.get("instance_type", {}).get("name", "")
    gpu_label = _GPU_FAMILIES.get(itype, itype or "GPU")

    packages = [
        Package(
            name=itype or "lambda-gpu-instance",
            version=status,
            ecosystem="lambda-cloud",
            purl=build_package_purl(
                ecosystem="lambda-cloud",
                name=itype or "lambda-gpu-instance",
                version=status,
            ),
        )
    ]

    server = MCPServer(
        name=f"lambda:{inst_name}",
        transport=TransportType.UNKNOWN,
        packages=packages,
        tools=[MCPTool(name=inst_name, description=f"Lambda Labs {gpu_label} instance ({region})")],
    )

    return Agent(
        name=f"lambda:{inst_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"lambda://{region}/{inst_id}",
        source="lambda-cloud",
        version=status,
        mcp_servers=[server],
        metadata={
            "gpu_type": gpu_label,
            "region": region,
            "status": status,
            "cloud_origin": build_cloud_origin(
                provider="lambda",
                service="compute",
                resource_type="gpu-instance",
                resource_id=inst_id,
                resource_name=inst_name,
                raw_identity={"id": inst_id, "region": region, "type": itype},
            ),
        },
    )


def discover(
    api_key: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover Lambda Labs GPU instances.

    Args:
        api_key: Lambda Cloud API key. Falls back to ``LAMBDA_API_KEY`` env var.

    Returns:
        (agents, warnings) tuple.
    """
    resolved_key = api_key or os.environ.get("LAMBDA_API_KEY", "")
    if not resolved_key:
        return [], [missing_api_key_warning("LAMBDA_API_KEY", "--lambda-api-key")]

    agents, warnings = collect_gpu_inventory(
        "lambda",
        lambda: inventory_list(_lambda_get("/instances", resolved_key), "data"),
        _instance_agent,
    )

    scope = tuple(f"lambda:region/{r}" for r in {a.metadata.get("region", "") for a in agents} if r)
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=scope or ("lambda:all",),
        permissions_used=("lambda-cloud:instances:read",),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    logger.info("Lambda Labs: discovered %d instance(s)", len(agents))
    return agents, warnings
