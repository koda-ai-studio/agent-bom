"""Typed conversion of Nebius REST inventory records.

ProtoJSON omits unset fields and renders int64 values as strings. A present
field of the wrong type, or a record with none of the identifying fields, is a
malformed record: it raises so the caller can warn and keep the listing going.
"""

from __future__ import annotations

import re
from typing import Any

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError
from .normalization import build_cloud_origin, build_package_purl

# AI workload image patterns (lowercase) — used to identify GPU/AI instances
_AI_IMAGE_PATTERNS = ("nvidia", "cuda", "pytorch", "tensorflow", "triton", "vllm", "tgi", "deepspeed", "nemo")
_PRESET_GPUS = re.compile(r"(\d{1,4})gpu-")


def _record(item: object) -> dict:
    if not isinstance(item, dict):
        raise CloudDiscoveryError("Invalid Nebius record")
    return item


def _section(record: dict, key: str) -> dict:
    """A nested object: absent is empty, present-but-not-an-object is malformed."""
    value = record.get(key, {})
    if not isinstance(value, dict):
        raise CloudDiscoveryError("Invalid Nebius record section")
    return value


def _text(record: dict, key: str, *, allow_int: bool = False) -> str | None:
    """A scalar field: absent is ``None``; null, objects and lists are malformed.

    ProtoJSON omits unset fields and renders int64 values as strings, so a
    present field is always a string (or an int from older payloads).
    """
    if key not in record:
        return None
    value = record[key]
    if isinstance(value, str):
        return value
    if allow_int and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise CloudDiscoveryError("Invalid Nebius record field")


def _count(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit() and len(value) <= 6:
        return int(value)
    raise CloudDiscoveryError("Invalid Nebius count")


def _instance_fields(inst: object) -> dict[str, Any]:
    """Read one compute instance in the nebius/api ``compute.v1.Instance`` shape.

    The official shape is ``metadata.{id,name}``, ``spec.resources.{platform,
    preset}`` and ``status.state``, with the GPU count encoded in the preset
    (``8gpu-128vcpu-1600gb``). The older flat ``id``/``name``/``platform_id``/
    ``resources.gpus`` shape is still accepted.
    """
    inst = _record(inst)
    meta, spec, legacy = _section(inst, "metadata"), _section(inst, "spec"), _section(inst, "resources")
    legacy_status = isinstance(inst.get("status"), str)
    status = _text(inst, "status") if legacy_status else _text(_section(inst, "status"), "state")
    resources = _section(spec, "resources")
    inst_id = _text(meta, "id") or _text(inst, "id")
    if not inst_id:
        raise CloudDiscoveryError("Unrecognised compute instance record")
    platform = _text(resources, "platform") or _text(inst, "platform_id") or ""
    preset = _text(resources, "preset") or ""
    preset_match = _PRESET_GPUS.match(preset)
    if preset_match:
        gpu_count = int(preset_match.group(1))
    else:
        gpu_count = _count(legacy.get("gpus", legacy.get("gpu_count", 0)))
    boot_disk = _section(inst, "boot_disk")
    image_id = _text(boot_disk, "image_id") or ""
    return {
        "id": inst_id,
        "name": _text(meta, "name") or _text(inst, "name") or inst_id,
        "platform": platform,
        "preset": preset,
        "gpu_count": gpu_count,
        "gpu_type": _text(legacy, "gpu_type") or platform,
        "status": status or "UNKNOWN",
        "image_name": _text(boot_disk, "image_name") or image_id,
    }


def _gpu_instance_agent(inst: object, project_id: str) -> Agent | None:
    """Build the agent for one compute instance, or ``None`` if it has no GPU."""
    fields = _instance_fields(inst)
    inst_id, inst_name, platform_id, status = fields["id"], fields["name"], fields["platform"], fields["status"]
    gpu_count, gpu_type, image_name = fields["gpu_count"], fields["gpu_type"], fields["image_name"]
    if not (gpu_count > 0 or "gpu" in platform_id.lower()):
        return None

    is_ai_workload = any(pat in image_name.lower() for pat in _AI_IMAGE_PATTERNS)
    desc_parts = [f"GPU:{gpu_type}x{gpu_count}", f"status:{status}"]
    if is_ai_workload:
        desc_parts.append(f"image:{image_name}")

    tools = [
        MCPTool(
            name=inst_name,
            description=f"Nebius GPU instance — {', '.join(desc_parts)}",
        )
    ]

    packages: list[Package] = []
    if is_ai_workload:
        packages.append(
            Package(
                name=image_name,
                version="detected",
                ecosystem="nebius-compute-image",
                purl=build_package_purl(ecosystem="nebius-compute-image", name=image_name, version="detected"),
            )
        )

    server = MCPServer(
        name=f"nebius-gpu:{inst_name}",
        transport=TransportType.UNKNOWN,
        tools=tools,
        packages=packages,
        env={"NEBIUS_INSTANCE_ID": inst_id},
    )

    return Agent(
        name=f"nebius-gpu:{inst_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"nebius://{project_id}/compute/{inst_id}",
        source="nebius-gpu",
        version=status,
        mcp_servers=[server],
        metadata={
            "gpu_count": gpu_count,
            "gpu_type": gpu_type,
            "ai_workload": is_ai_workload,
            "cloud_origin": build_cloud_origin(
                provider="nebius",
                service="compute",
                resource_type="gpu-instance",
                resource_id=inst_id,
                resource_name=inst_name,
                project_id=project_id,
                raw_identity={
                    "id": inst_id,
                    "name": inst_name,
                    "platform_id": platform_id,
                    "status": status,
                    **({"preset": fields["preset"]} if fields["preset"] else {}),
                },
            ),
        },
    )


def _container_service_agent(svc: object, project_id: str) -> Agent:
    """Convert one serverless container; every identity and image field must be a string."""
    svc = _record(svc)
    svc_id = _text(svc, "id") or _text(svc, "name")
    if not svc_id:
        raise CloudDiscoveryError("Unrecognised container service record")
    svc_name = _text(svc, "name") or svc_id
    image = (_text(svc, "image") or "").strip()
    if image:
        server = MCPServer(name=f"nebius-container:{svc_name}", command="docker", args=["run", image], transport=TransportType.STDIO)
    else:
        server = MCPServer(name=f"nebius-container:{svc_name}", transport=TransportType.UNKNOWN)
    return Agent(
        name=f"nebius-container:{svc_name}",
        agent_type=AgentType.CUSTOM,
        config_path=f"nebius://{project_id}/containers/{svc_id}",
        source="nebius-container",
        mcp_servers=[server],
        metadata={
            "cloud_origin": build_cloud_origin(
                provider="nebius",
                service="containers",
                resource_type="container",
                resource_id=svc_id,
                resource_name=svc_name,
                project_id=project_id,
                raw_identity={"id": svc_id, "name": svc_name, "image": image},
            )
        },
    )
