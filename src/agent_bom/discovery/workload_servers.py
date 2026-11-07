"""Read MCP server settings out of Compose services and Kubernetes containers."""

from __future__ import annotations

from typing import Any

from agent_bom.models import TransportType


def compose_service_env(raw_env: object) -> dict[str, str]:
    """A Compose service's environment, written either as ``KEY=VALUE`` entries or as a mapping."""
    env: dict[str, str] = {}
    if isinstance(raw_env, list):
        for entry in raw_env:
            if isinstance(entry, str) and "=" in entry:
                key, _, value = entry.partition("=")
                env[key] = value
    elif isinstance(raw_env, dict):
        env = {key: str(value) for key, value in raw_env.items()}
    return env


def k8s_container_endpoint(container: dict[str, Any], labels: dict[str, Any], pod_name: str, pod_ns: str) -> tuple[TransportType, str]:
    """Transport and in-cluster URL; a container exposing a port is assumed to serve SSE/HTTP."""
    ports = container.get("ports", [])
    if not ports:
        return TransportType.STDIO, ""
    port_num = ports[0].get("containerPort", 8000)
    svc_name = labels.get("app", labels.get("app.kubernetes.io/name", pod_name))
    return TransportType.SSE, f"http://{svc_name}.{pod_ns}.svc.cluster.local:{port_num}"
