"""Ollama model discovery from a selected endpoint or local manifests.

Discovers models from the Ollama API (http://localhost:11434) and/or
the ``~/.ollama/models`` manifest directory.  No extra dependencies required.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import httpx

from agent_bom.cloud.serving_runtimes import EndpointObservation, ServedModel, serving_evidence
from agent_bom.discovery_envelope import RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package
from agent_bom.security import SecurityError, sanitize_error, sanitize_text, validate_url

logger = logging.getLogger(__name__)

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_MANIFEST_DIR = Path.home() / ".ollama" / "models" / "manifests" / "registry.ollama.ai"


def discover(
    host: str | None = None,
    timeout: float = 5.0,
) -> tuple[list[Agent], list[str]]:
    """Discover models within the selected Ollama collection scope.

    Strategy:
    1. Try the Ollama HTTP API (``/api/tags``) for running server inventory.
    2. Only for the implicit default, fall back to local manifests on disk.
       A configured endpoint never substitutes inventory from this machine.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.
    """
    agents: list[Agent] = []
    warnings: list[str] = []

    configured_host = host or os.environ.get("OLLAMA_HOST")
    resolved_host: str = configured_host or _DEFAULT_OLLAMA_HOST

    # ── Strategy 1: Ollama API ───────────────────────────────────────────
    outcome: dict[str, Any] = {}
    api_models = _discover_via_api(resolved_host, outcome=outcome, timeout=timeout)
    status = str(outcome.get("status", "success" if api_models is not None else "unavailable"))
    if api_models is not None:
        if status == "partial":
            warnings.append(
                f"Ollama inventory at {resolved_host} is partial: {outcome.get('dropped', 0)} record(s) did not match /api/tags."
            )
        agents = _agents_from_api(api_models, resolved_host, status=status)

        attach_envelope_to_agents(
            agents,
            scan_mode=ScanMode.RUNTIME_PROBE,
            discovery_scope=(f"ollama:host/{resolved_host}",),
            permissions_used=("ollama:GET /api/tags",),
            redaction_status=RedactionStatus.NOT_APPLICABLE,
        )
        return agents, warnings

    label = {"timeout": "timed out"}.get(status, status)
    if configured_host:
        warnings.append(f"Ollama discovery incomplete: configured endpoint {label}; local manifests were not substituted.")
        return agents, warnings

    # ── Strategy 2: Manifest directory scan ───────────────────────────────
    if _MANIFEST_DIR.is_dir():
        manifests = _discover_from_manifests()
        if manifests:
            warnings.append(f"Ollama API {label}; inventory is from local manifests only, not confirmed serving models.")
            for model_name, model_tag, manifest_path in manifests:
                server = MCPServer(
                    name=f"ollama/{model_name}:{model_tag}",
                    command="ollama",
                    args=["run", f"{model_name}:{model_tag}"],
                    packages=[
                        Package(
                            name=model_name,
                            version=model_tag,
                            ecosystem="ollama",
                        )
                    ],
                )
                agent = Agent(
                    name=f"ollama-model-{model_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=str(manifest_path),
                    source="ollama-manifest",
                    mcp_servers=[server],
                )
                agents.append(agent)
        else:
            warnings.append("Ollama manifest directory found but no models detected")
    else:
        warnings.append(f"Ollama not detected (API at {resolved_host} {label}, no manifests at {_MANIFEST_DIR})")

    # Manifest inventory establishes downloaded artifacts, not API availability.
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.LOCAL_ONLY,
        discovery_scope=(f"ollama:manifest_dir/{_MANIFEST_DIR}",),
        permissions_used=("filesystem:read manifests",),
        redaction_status=RedactionStatus.NOT_APPLICABLE,
    )
    return agents, warnings


def _agents_from_api(api_models: list[dict], host: str, status: str = "success") -> list[Agent]:
    """Project API model metadata without inventing serving configuration."""
    agents: list[Agent] = []
    observation = EndpointObservation(
        runtime="ollama",
        endpoint=host.rstrip("/"),
        status=status,
        permissions_used=("ollama:GET /api/tags",),
    )
    for model in api_models:
        name = model.get("name", "unknown")
        size = model.get("size", 0)
        family = model.get("details", {}).get("family", "")
        param_size = model.get("details", {}).get("parameter_size", "")
        quant = model.get("details", {}).get("quantization_level", "")
        fmt = model.get("details", {}).get("format", "")

        tools = []
        meta_parts = []
        if family:
            meta_parts.append(f"family:{family}")
        if param_size:
            meta_parts.append(f"params:{param_size}")
        if quant:
            meta_parts.append(f"quant:{quant}")
        if fmt:
            meta_parts.append(f"format:{fmt}")
        if size:
            size_gb = size / (1024**3)
            meta_parts.append(f"size:{size_gb:.1f}GB")

        tools.append(
            MCPTool(
                name=name,
                description=f"Ollama model — {', '.join(meta_parts)}" if meta_parts else "Ollama model",
            )
        )

        # Model name could be "llama3:8b" or "qwen2.5-coder:7b-instruct-q4_K_M"
        base_name = name.split(":")[0] if ":" in name else name
        tag = name.split(":")[1] if ":" in name else "latest"

        server = MCPServer(
            name=f"ollama/{name}",
            command="ollama",
            args=["run", name],
            tools=tools,
            packages=[
                Package(
                    name=base_name,
                    version=tag,
                    ecosystem="ollama",
                )
            ],
        )

        digest = model.get("digest")
        served = ServedModel(served_name=name, artifact_ref=name, digest=digest if isinstance(digest, str) and digest else None)
        # The full name:tag is the artifact identity; two tags of one model are distinct assets.
        agent = Agent(
            name=f"ollama-model-{name}",
            agent_type=AgentType.CUSTOM,
            config_path=host,
            source="ollama-api",
            mcp_servers=[server],
            metadata={"serving_evidence": serving_evidence(observation, served)},
        )
        agents.append(agent)
    return agents


def _discover_via_api(host: str, outcome: dict[str, Any] | None = None, timeout: float = 5.0) -> list[dict] | None:
    """Try to get model list from Ollama HTTP API. Returns None if unreachable or refused.

    ``outcome["status"]`` records ``success``, ``partial``, ``denied``, ``timeout``
    or ``unavailable`` so callers never describe a refusal as an absent server.
    """
    result: dict[str, Any] = outcome if outcome is not None else {}
    result["status"] = "unavailable"
    url = f"{host.rstrip('/')}/api/tags"
    try:
        # Ollama normally listens on localhost or a private address, so private
        # targets stay allowed; non-HTTP schemes and cloud metadata are refused.
        validate_url(url, allowed_schemes=("http", "https"), allow_private=True)
    except SecurityError as exc:
        logger.warning("Ollama endpoint refused by outbound URL policy: %s", sanitize_text(sanitize_error(exc)))
        return None
    try:
        resp = httpx.get(url, timeout=timeout)
        if resp.status_code == 200:
            return _api_models(resp, result)
        if resp.status_code in (401, 403):
            result["status"] = "denied"
            return None
    except httpx.TimeoutException as exc:
        result["status"] = "timeout"
        logger.debug("Ollama httpx API probe timed out: %s", sanitize_text(exc))
        return None
    except (httpx.HTTPError, OSError, ValueError) as exc:
        logger.debug("Ollama httpx API probe failed: %s", sanitize_text(exc))

    # Fallback: try with sync httpx client (retry-capable)
    try:
        from agent_bom.http_client import sync_get

        fallback_resp = sync_get(url, timeout=3)
        if fallback_resp is not None and fallback_resp.status_code == 200:
            return _api_models(fallback_resp, result)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        logger.debug("Ollama sync API probe failed: %s", sanitize_text(exc))

    return None


def _api_models(response: httpx.Response, outcome: dict[str, Any] | None = None) -> list[dict] | None:
    """Only an explicit models list establishes a successful inventory.

    Malformed entries are dropped and reported as partial; a list with no
    usable entry at all is not a verified inventory.
    """
    data = response.json()
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list):
        return None
    valid = [model for model in models if isinstance(model, dict) and isinstance(model.get("name"), str) and model["name"]]
    dropped = len(models) - len(valid)
    if dropped and not valid:
        return None
    if outcome is not None:
        outcome["status"] = "partial" if dropped else "success"
        outcome["dropped"] = dropped
    return valid


def _discover_from_manifests() -> list[tuple[str, str, Path]]:
    """Scan ~/.ollama/models/manifests for downloaded model tags.

    Returns list of (model_name, tag, manifest_path).
    """
    results: list[tuple[str, str, Path]] = []

    if not _MANIFEST_DIR.is_dir():
        return results

    # Structure: manifests/registry.ollama.ai/library/<model>/<tag>
    library_dir = _MANIFEST_DIR / "library"
    if not library_dir.is_dir():
        return results

    for model_dir in sorted(library_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        model_name = model_dir.name
        for tag_file in sorted(model_dir.iterdir()):
            if tag_file.is_file():
                tag = tag_file.name
                results.append((model_name, tag, tag_file))

    return results
