"""Auto-discover MCP client configurations on the system."""

from __future__ import annotations

import glob as glob_mod
import json
import logging
import os
import platform
import shutil
import subprocess
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import yaml  # type: ignore[import-untyped]
from rich.console import Console
from rich.markup import escape

# Re-export parser functions for backward compatibility
from agent_bom.discovery.config_parsers import (  # noqa: F401
    _DANGEROUS_HOOK_PATTERNS,
    _parse_docker_mcp_catalog,
    audit_cortex_hooks,
    audit_cortex_permissions,
    parse_claude_json_projects,
    parse_codex_config,
    parse_cortex_code_metadata,
    parse_goose_config,
    parse_mcp_config,
    parse_snowflake_connections,
)
from agent_bom.discovery.k8s_hosting import node_provider_ids, pod_hosting_metadata
from agent_bom.discovery.local_sources import discover_docker_mcp as discover_docker_mcp
from agent_bom.discovery.local_sources import logger as logger
from agent_bom.discovery.platform_config import COMPOSE_FILE_NAMES as COMPOSE_FILE_NAMES
from agent_bom.discovery.platform_config import CONFIG_LOCATIONS as CONFIG_LOCATIONS
from agent_bom.discovery.platform_config import _parse_project_config_file as _parse_project_config_file
from agent_bom.discovery.platform_config import _project_config_candidates as _project_config_candidates
from agent_bom.discovery.platform_config import _project_search_dir as _project_search_dir
from agent_bom.discovery.platform_config import _read_json_config_no_symlink as _read_json_config_no_symlink
from agent_bom.discovery.platform_config import detect_installed_agents as detect_installed_agents
from agent_bom.discovery.platform_config import expand_path as expand_path
from agent_bom.discovery.platform_config import get_platform as get_platform
from agent_bom.floating_refs import classify_image_reference
from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer, TransportType
from agent_bom.security import sanitize_env_vars, sanitize_log_label

console = Console(stderr=True)


def _display_label(value: object, max_len: int = 500) -> str:
    return escape(sanitize_log_label(value, max_len=max_len))


# Config file locations per platform

# Map agent types to their CLI binary names for installed-but-not-configured detection

# Project-level config files to search for


# Custom parsers for non-JSON config formats


# Additional install signals beyond binary detection


def discover_global_configs(agent_types: Optional[list[AgentType]] = None, *, quiet: bool = False) -> list[Agent]:
    """Discover all global MCP client configurations."""
    agents: list[Agent] = []
    sys_platform = get_platform()
    pending_cortex_metadata: dict = {}
    cortex_metadata_path: Optional[str] = None

    if agent_types is None:
        agent_types = list(CONFIG_LOCATIONS.keys())

    for agent_type in agent_types:
        locations = CONFIG_LOCATIONS.get(agent_type, {})
        platform_paths = locations.get(sys_platform, [])

        for path_str in platform_paths:
            # Handle glob patterns (e.g., JetBrains ~/Library/.../JetBrains/*/mcp.json)
            expanded_base = os.path.expanduser(path_str)
            if "*" in expanded_base:
                resolved_paths = [Path(p).resolve() for p in glob_mod.glob(expanded_base)]
            else:
                resolved_paths = [expand_path(path_str)]

            # Filter out symlinks that resolve outside expected config directories
            # to prevent symlink-based information disclosure attacks.
            safe_paths: list[Path] = []
            for rp in resolved_paths:
                # Skip symlinks whose target differs from the link path's parent tree
                raw_path = Path(os.path.expanduser(path_str)) if "*" not in path_str else rp
                if raw_path.is_symlink() and not rp.is_relative_to(raw_path.parent):
                    logger.warning(
                        "Skipping symlink pointing outside parent: %s -> %s",
                        sanitize_log_label(raw_path),
                        sanitize_log_label(rp),
                    )
                    continue
                safe_paths.append(rp)

            for config_path in safe_paths:
                if not config_path.exists():
                    continue
                try:
                    servers: list[MCPServer] = []
                    metadata: dict = {}

                    # Cortex Code auxiliary files (permissions, hooks, settings)
                    if agent_type == AgentType.CORTEX_CODE and config_path.name != "mcp.json":
                        metadata = parse_cortex_code_metadata(str(config_path))
                        if metadata:
                            # Buffer the findings and flush after the path loop so they
                            # attach regardless of whether the mcp.json (and thus the
                            # CORTEX_CODE agent) is discovered before or after this file.
                            pending_cortex_metadata.update(metadata)
                            cortex_metadata_path = str(config_path)
                        continue

                    # Custom parsers for non-JSON formats
                    if agent_type == AgentType.CODEX_CLI:
                        servers = parse_codex_config(str(config_path))
                    elif agent_type == AgentType.GOOSE:
                        servers = parse_goose_config(str(config_path))
                    elif agent_type == AgentType.SNOWFLAKE_CLI:
                        servers = parse_snowflake_connections(str(config_path))
                    else:
                        # Default JSON parsing
                        config_data = _read_json_config_no_symlink(config_path)
                        servers = parse_mcp_config(config_data, str(config_path))

                        # Claude Code ~/.claude.json has project-level MCP servers
                        if agent_type == AgentType.CLAUDE_CODE and config_path.name == ".claude.json":
                            servers = servers + parse_claude_json_projects(config_data, str(config_path))

                    if servers:
                        agent = Agent(
                            name=agent_type.value,
                            agent_type=agent_type,
                            config_path=str(config_path),
                            mcp_servers=servers,
                        )
                        agents.append(agent)
                        if not quiet:
                            console.print(
                                f"  [green]✓[/green] Found {_display_label(agent_type.value)} "
                                f"with {len(servers)} MCP server(s): {_display_label(config_path)}"
                            )
                except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
                    if not quiet:
                        console.print(f"  [yellow]⚠[/yellow] Error parsing {_display_label(config_path)}: {_display_label(e)}")

    if pending_cortex_metadata:
        cortex_agent = next((a for a in agents if a.agent_type == AgentType.CORTEX_CODE), None)
        if cortex_agent is not None:
            cortex_agent.metadata.update(pending_cortex_metadata)
        else:
            # No mcp.json was found, but the auxiliary security findings still
            # matter — surface them on a standalone CORTEX_CODE agent.
            agents.append(
                Agent(
                    name=AgentType.CORTEX_CODE.value,
                    agent_type=AgentType.CORTEX_CODE,
                    config_path=cortex_metadata_path or AgentType.CORTEX_CODE.value,
                    status=AgentStatus.INSTALLED_NOT_CONFIGURED,
                    metadata=pending_cortex_metadata,
                )
            )

    return agents


def discover_project_configs(project_dir: Optional[str] = None) -> list[Agent]:
    """Discover project-level MCP configurations."""
    agents = []
    search_dir = _project_search_dir(project_dir)

    for config_path in _project_config_candidates(project_dir):
        if config_path.exists():
            try:
                servers = _parse_project_config_file(config_path)

                if servers:
                    agent = Agent(
                        name=f"project:{search_dir.name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(config_path),
                        source="project-config",
                        mcp_servers=servers,
                        metadata={"project_root": str(search_dir.resolve())},
                    )
                    agents.append(agent)
                    console.print(
                        f"  [green]✓[/green] Found project config with {len(servers)} MCP server(s): {_display_label(config_path)}"
                    )
            except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
                console.print(f"  [yellow]⚠[/yellow] Error parsing {_display_label(config_path)}: {_display_label(e)}")

    return agents


# Docker Compose file names to search for MCP server services

# Image prefixes that indicate MCP servers in Docker Compose
MCP_IMAGE_PREFIXES = (
    "mcp/",
    "ghcr.io/modelcontextprotocol/",
    "modelcontextprotocol/",
)


def discover_compose_mcp_servers(project_dir: Optional[str] = None) -> Optional[Agent]:
    """Discover MCP servers defined in Docker Compose files.

    Scans ``docker-compose.yml`` / ``compose.yml`` for services whose images
    match known MCP server patterns (e.g. ``mcp/playwright``, ``mcp/fetch``).
    """
    from agent_bom.models import Package

    search_dir = Path(project_dir) if project_dir else Path.cwd()
    compose_path: Optional[Path] = None
    for name in COMPOSE_FILE_NAMES:
        candidate = search_dir / name
        if candidate.exists():
            compose_path = candidate
            break

    if not compose_path:
        return None

    try:
        compose_data = yaml.safe_load(compose_path.read_text())
    except (OSError, ValueError):
        return None

    if not compose_data or not isinstance(compose_data, dict):
        return None

    services = compose_data.get("services", {})
    if not isinstance(services, dict):
        return None

    mcp_servers: list[MCPServer] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        image = svc_def.get("image", "")
        if not image:
            continue

        # Check if this service uses a known MCP server image
        is_mcp = any(image.startswith(prefix) for prefix in MCP_IMAGE_PREFIXES)
        if not is_mcp:
            continue

        # Extract version from image tag
        pkg_version = "latest"
        pkg_name = image
        if "@sha256:" in image:
            pkg_name = image.split("@")[0]
            pkg_version = image.split("@sha256:")[1][:12]
        elif ":" in image and not image.startswith("ghcr.io:"):
            parts = image.rsplit(":", 1)
            pkg_name = parts[0]
            pkg_version = parts[1]

        # Extract env vars (list or dict format)
        raw_env = svc_def.get("environment", {})
        env: dict[str, str] = {}
        if isinstance(raw_env, list):
            for entry in raw_env:
                if isinstance(entry, str) and "=" in entry:
                    k, _, v = entry.partition("=")
                    env[k] = v
        elif isinstance(raw_env, dict):
            env = {k: str(v) for k, v in raw_env.items()}

        # Redact sensitive values
        env = sanitize_env_vars(env)

        packages = [
            Package(
                name=pkg_name,
                version=pkg_version,
                ecosystem="docker",
                is_direct=True,
                floating_reference=(floating := classify_image_reference(image)) is not None,
                floating_reference_reason=floating.reason if floating else None,
            )
        ]

        server = MCPServer(
            name=svc_name,
            command=f"docker compose up {svc_name}",
            args=[],
            env=env,
            transport=TransportType.STDIO,
            packages=packages,
            config_path=str(compose_path),
            security_warnings=[floating.to_security_warning()] if floating else [],
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    return Agent(
        name="docker-compose",
        agent_type=AgentType.CUSTOM,
        config_path=str(compose_path),
        mcp_servers=mcp_servers,
    )


# ─── MCP process command patterns ─────────────────────────────────────────────
#
# Substrings that, when found in a process's command line, indicate it may be
# an MCP server.  All comparisons are case-insensitive.
_MCP_PROCESS_PATTERNS: tuple[str, ...] = (
    "mcp-server",
    "@modelcontextprotocol/",
    "mcp_server",
    "mcpserver",
    "uvx mcp",
    "npx mcp",
    "python -m mcp",
)

# Env vars that signal an MCP server process (prefix match, uppercase)
_MCP_ENV_SIGNALS: tuple[str, ...] = ("MCP_SERVER", "MCP_PORT", "MCP_TRANSPORT", "MCP_HOST")


def discover_running_processes() -> Optional[Agent]:
    """Discover locally running MCP server processes via psutil.

    Iterates all processes on the host and matches command lines against
    known MCP server patterns (npm/npx @modelcontextprotocol/*, uvx mcp-server-*,
    python -m mcp*, etc.).  Each matching process becomes an MCPServer entry.

    Requires ``psutil`` (``pip install psutil`` or ``agent-bom[runtime]``).
    Returns None if psutil is not installed or no MCP processes are found.
    """
    try:
        import psutil
    except ImportError:
        logger.debug("psutil not installed — skipping process discovery (pip install psutil)")
        return None

    mcp_servers: list[MCPServer] = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "environ", "cwd"]):
        try:
            info = proc.info
            cmdline: list[str] = info.get("cmdline") or []
            if not cmdline:
                continue

            cmd_str = " ".join(cmdline).lower()
            if not any(pat in cmd_str for pat in _MCP_PROCESS_PATTERNS):
                continue

            # Try to read environment (may raise AccessDenied on some platforms)
            try:
                raw_env: dict[str, str] = info.get("environ") or {}
            except (psutil.AccessDenied, psutil.ZombieProcess):
                raw_env = {}

            # Check env signals too — catch MCP servers not matching cmd patterns
            env_signals = any(k.upper().startswith(_MCP_ENV_SIGNALS) for k in raw_env)
            if not any(pat in cmd_str for pat in _MCP_PROCESS_PATTERNS) and not env_signals:
                continue

            env = sanitize_env_vars({k: str(v) for k, v in raw_env.items()})

            # Derive a human-readable name from the command
            args = cmdline[1:] if len(cmdline) > 1 else []
            # Use the first arg that looks like a package/module name as the server name
            name_parts = [p for p in args if p.startswith("@") or "mcp" in p.lower()]
            server_name = name_parts[0].split("/")[-1] if name_parts else f"process-{info['pid']}"

            # Determine transport from env or args
            transport = TransportType.STDIO
            if "--transport" in args:
                idx = args.index("--transport")
                if idx + 1 < len(args):
                    t = args[idx + 1].lower()
                    if "sse" in t:
                        transport = TransportType.SSE
                    elif "http" in t:
                        transport = TransportType.STREAMABLE_HTTP

            working_dir = info.get("cwd")

            server = MCPServer(
                name=server_name,
                command=cmdline[0],
                args=args,
                env=env,
                transport=transport,
                config_path=f"pid:{info['pid']}",
                working_dir=working_dir,
            )
            mcp_servers.append(server)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not mcp_servers:
        return None

    return Agent(
        name="running-processes",
        agent_type=AgentType.CUSTOM,
        config_path="psutil://processes",
        mcp_servers=mcp_servers,
        source="process",
    )


def discover_container_labels() -> Optional[Agent]:
    """Discover MCP server containers running locally via Docker.

    Uses ``docker ps`` + ``docker inspect`` (no SDK required) to enumerate
    running containers and identify those whose images, labels, or environment
    variables indicate an MCP server.

    Returns None if Docker is not available or no MCP containers are found.
    """
    if not shutil.which("docker"):
        return None

    try:
        ps_result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if ps_result.returncode != 0:
        return None

    container_ids = [cid.strip() for cid in ps_result.stdout.splitlines() if cid.strip()]
    if not container_ids:
        return None

    mcp_servers: list[MCPServer] = []

    for cid in container_ids:
        try:
            inspect_result = subprocess.run(
                ["docker", "inspect", "--format", "{{json .}}", cid],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            continue

        if inspect_result.returncode != 0:
            continue

        try:
            info = json.loads(inspect_result.stdout)
        except (json.JSONDecodeError, ValueError):
            continue

        # Normalise: docker inspect returns a list when called without --format json
        if isinstance(info, list):
            if not info:
                continue
            info = info[0]

        image_name: str = info.get("Config", {}).get("Image", "") or ""
        labels: dict[str, str] = info.get("Config", {}).get("Labels") or {}
        cmd: list[str] = info.get("Config", {}).get("Cmd") or []
        entrypoint: list[str] = info.get("Config", {}).get("Entrypoint") or []

        # Collect raw env list → dict
        raw_env_list: list[str] = info.get("Config", {}).get("Env") or []
        raw_env: dict[str, str] = {}
        for entry in raw_env_list:
            if "=" in entry:
                k, _, v = entry.partition("=")
                raw_env[k] = v

        image_lower = image_name.lower()
        label_vals = " ".join(labels.values()).lower()
        label_keys = " ".join(labels.keys()).lower()
        cmd_str = " ".join(cmd + entrypoint).lower()
        env_keys = " ".join(raw_env.keys()).upper()

        is_mcp = (
            "mcp" in image_lower
            or any(p in image_lower for p in ("modelcontextprotocol", "mcp-server", "mcp_server"))
            or "mcp" in label_vals
            or "mcp" in label_keys
            or "mcp" in cmd_str
            or any(k.startswith(_MCP_ENV_SIGNALS) for k in env_keys.split())
        )

        if not is_mcp:
            continue

        env = sanitize_env_vars(raw_env)

        # Name: prefer label, fall back to image basename, then short container ID
        server_name = (
            labels.get("mcp.name") or labels.get("org.opencontainers.image.title") or image_lower.split("/")[-1].split(":")[0] or cid[:12]
        )

        # Transport: SSE if any port is exposed, else STDIO
        ports = info.get("NetworkSettings", {}).get("Ports") or {}
        transport = TransportType.SSE if ports else TransportType.STDIO
        url: Optional[str] = None
        if ports:
            for port_spec, bindings in ports.items():
                if bindings:
                    host_port = bindings[0].get("HostPort")
                    if host_port:
                        url = f"http://localhost:{host_port}"
                        break

        from agent_bom.models import Package

        packages = [
            Package(
                name=image_name.split(":")[0],
                version=image_name.split(":")[-1] if ":" in image_name else "latest",
                ecosystem="docker",
                is_direct=True,
                floating_reference=(floating := classify_image_reference(image_name)) is not None,
                floating_reference_reason=floating.reason if floating else None,
            )
        ]

        server = MCPServer(
            name=server_name,
            command=f"docker run {image_name}",
            args=[],
            env=env,
            transport=transport,
            url=url,
            packages=packages,
            config_path=f"docker://{cid[:12]}",
            security_warnings=[floating.to_security_warning()] if floating else [],
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    return Agent(
        name="docker-containers",
        agent_type=AgentType.CUSTOM,
        config_path="docker://localhost",
        mcp_servers=mcp_servers,
        source="container",
    )


# ── Kubernetes MCP CRD / label / env discovery ───────────────────────────────

# MCP signals in pod metadata and container specs
_K8S_MCP_LABELS = ("mcp.server", "mcp-server", "mcp.io/server", "app.kubernetes.io/component=mcp")
_K8S_MCP_IMAGE_PATTERNS = ("mcp-server", "mcp_server", "/mcp:", "-mcp:")
_K8S_MCP_ENV_PREFIX = "MCP_"
_K8S_MCP_CRD_RESOURCE = "mcpservers"  # custom resource: mcpservers.mcp.io


def discover_k8s_mcp_servers(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
) -> Optional[Agent]:
    """Discover MCP servers declared as Kubernetes pods, services, or CRDs.

    Scans pods for MCP signals (labels, annotations, image names, env vars) and
    optionally queries for ``mcpservers.mcp.io`` custom resources if that CRD
    is installed.  Uses ``kubectl`` — no Python SDK required.

    Args:
        namespace: Kubernetes namespace to query (ignored when ``all_namespaces=True``).
        all_namespaces: Query all namespaces (``kubectl ... -A``).
        context: kubectl context to use (uses current context if ``None``).

    Returns:
        An Agent with ``source="kubernetes"`` or ``None`` if kubectl is absent
        or no MCP pods/CRDs are found.
    """
    if not shutil.which("kubectl"):
        return None

    def _kubectl(*args: str) -> Optional[dict]:
        cmd = ["kubectl", *args]
        if context:
            cmd += ["--context", context]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return None
            return json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    # ── 1. Pod-level scan ────────────────────────────────────────────────────
    pod_args = ["get", "pods", "-o", "json"]
    if all_namespaces:
        pod_args.append("-A")
    else:
        pod_args += ["-n", namespace]

    pod_data = _kubectl(*pod_args)

    mcp_servers: list[MCPServer] = []
    seen_names: set[str] = set()
    provider_ids = node_provider_ids(_kubectl) if (pod_data or {}).get("items") else {}
    for pod in (pod_data or {}).get("items", []):
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        pod_ns = meta.get("namespace", namespace)
        labels = meta.get("labels", {})
        annotations = meta.get("annotations", {})
        spec = pod.get("spec", {})

        # Check label signals
        label_str = " ".join(f"{k}={v}" for k, v in labels.items()).lower()
        annotation_keys = " ".join(annotations.keys()).lower()
        has_label_signal = any(sig.lower() in label_str or sig.lower() in annotation_keys for sig in _K8S_MCP_LABELS)

        containers = spec.get("containers", [])
        for container in containers:
            image = container.get("image", "").lower()
            env_vars: list[dict] = container.get("env", [])
            env_names = " ".join(e.get("name", "") for e in env_vars)

            has_image_signal = any(pat in image for pat in _K8S_MCP_IMAGE_PATTERNS)
            has_env_signal = _K8S_MCP_ENV_PREFIX in env_names

            if not (has_label_signal or has_image_signal or has_env_signal):
                continue

            transport = TransportType.STDIO
            url = ""
            ports = container.get("ports", [])
            if ports:
                # Assume SSE/HTTP if the container exposes a port
                transport = TransportType.SSE
                port_num = ports[0].get("containerPort", 8000)
                svc_name = labels.get("app", labels.get("app.kubernetes.io/name", pod_name))
                url = f"http://{svc_name}.{pod_ns}.svc.cluster.local:{port_num}"

            raw_env = {e.get("name", ""): e.get("value", "") for e in env_vars if e.get("name")}
            env = sanitize_env_vars(raw_env)

            container_name = container.get("name", "mcp")
            server_name = f"{pod_ns}/{pod_name}/{container_name}"
            if server_name in seen_names:
                continue
            seen_names.add(server_name)

            server = MCPServer(
                name=server_name,
                command="",  # pod containers don't have a local command to launch
                env=env,
                transport=transport,
                url=url,
                config_path=f"k8s://{pod_ns}/{pod_name}",
                connection_metadata=pod_hosting_metadata(pod, cluster=context or "", provider_ids=provider_ids),
            )
            mcp_servers.append(server)

    # ── 2. MCP CRD scan (mcpservers.mcp.io) ─────────────────────────────────
    crd_args = ["get", _K8S_MCP_CRD_RESOURCE, "-o", "json"]
    if all_namespaces:
        crd_args.append("-A")
    else:
        crd_args += ["-n", namespace]

    crd_data = _kubectl(*crd_args)

    for item in (crd_data or {}).get("items", []):
        meta = item.get("metadata", {})
        crd_name = meta.get("name", "unknown")
        crd_ns = meta.get("namespace", namespace)
        spec = item.get("spec", {})

        url = spec.get("url", spec.get("endpoint", ""))
        transport = TransportType.SSE if url else TransportType.STDIO
        server_name = f"{crd_ns}/{crd_name}"

        if server_name in seen_names:
            continue
        seen_names.add(server_name)

        server = MCPServer(
            name=server_name,
            command=spec.get("command", ""),
            transport=transport,
            url=url,
            config_path=f"k8s-crd://{crd_ns}/{crd_name}",
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    ns_label = "all-namespaces" if all_namespaces else namespace
    return Agent(
        name=f"kubernetes-mcp/{ns_label}",
        agent_type=AgentType.CUSTOM,
        config_path=f"k8s://{ns_label}",
        mcp_servers=mcp_servers,
        source="kubernetes",
    )


def discover_all(
    project_dir: Optional[str] = None,
    dynamic: bool = False,
    dynamic_max_depth: int = 4,
    include_processes: bool = False,
    include_containers: bool = False,
    include_k8s_mcp: bool = False,
    k8s_namespace: str = "default",
    k8s_all_namespaces: bool = False,
    k8s_context: Optional[str] = None,
) -> list[Agent]:
    """Run discovery for the local machine or a specific project.

    Args:
        project_dir: Optional project directory to scan. When provided,
            discovery is scoped to that project instead of ambient
            machine-wide MCP configuration.
        dynamic: Enable dynamic content-based discovery layer.
        dynamic_max_depth: Maximum depth for dynamic filesystem scanning.
        include_processes: Also scan running host processes for MCP servers (psutil).
        include_containers: Also scan running Docker containers for MCP servers.
        include_k8s_mcp: Scan Kubernetes cluster for MCP pods and CRDs (kubectl).
        k8s_namespace: Kubernetes namespace to query (default: "default").
        k8s_all_namespaces: Query all Kubernetes namespaces.
        k8s_context: kubectl context to use (uses current context if None).
    """
    from agent_bom.core.terminal import safe_emoji

    console.print(f"\n[bold blue]{safe_emoji('🔍', '>')} Discovering MCP configurations...[/bold blue]\n")
    project_search_dir = str(_project_search_dir(project_dir)) if project_dir else None

    if project_dir:
        agents = discover_project_configs(project_dir)
    else:
        agents = discover_global_configs()
        agents.extend(discover_project_configs())

    # Docker Compose MCP server discovery
    compose_agent = discover_compose_mcp_servers(project_search_dir)
    if compose_agent:
        console.print(
            f"  [green]✓[/green] Found {len(compose_agent.mcp_servers)} MCP server(s) "
            f"in Docker Compose: {_display_label(compose_agent.config_path)}"
        )
        agents.append(compose_agent)

    if not project_dir:
        # Tooling and desktop integrations are ambient host discovery surfaces,
        # so skip them when the caller explicitly scopes discovery to a project.
        # Docker Desktop MCP Toolkit discovery
        docker_agent = discover_docker_mcp()
        if docker_agent:
            if docker_agent.mcp_servers:
                total_tools = sum(len(s.tools) for s in docker_agent.mcp_servers)
                console.print(
                    f"  [green]✓[/green] Found docker-mcp with "
                    f"{len(docker_agent.mcp_servers)} enabled server(s), "
                    f"{total_tools} tool(s) (via Docker Desktop MCP Toolkit)"
                )
            else:
                console.print("  [dim]  docker-mcp: installed but not configured[/dim]")
            agents.append(docker_agent)

    # Running process discovery (opt-in, requires psutil)
    if include_processes and not project_dir:
        proc_agent = discover_running_processes()
        if proc_agent:
            console.print(f"  [green]✓[/green] Found {len(proc_agent.mcp_servers)} MCP server process(es) via psutil")
            agents.append(proc_agent)
        else:
            console.print("  [dim]  process scan: no MCP server processes found[/dim]")

    # Docker container discovery (opt-in)
    if include_containers and not project_dir:
        container_agent = discover_container_labels()
        if container_agent:
            console.print(f"  [green]✓[/green] Found {len(container_agent.mcp_servers)} MCP container(s) via docker inspect")
            agents.append(container_agent)
        else:
            console.print("  [dim]  container scan: no MCP containers found (or docker not running)[/dim]")

    # Kubernetes MCP pod/CRD discovery (opt-in)
    if include_k8s_mcp:
        k8s_agent = discover_k8s_mcp_servers(
            namespace=k8s_namespace,
            all_namespaces=k8s_all_namespaces,
            context=k8s_context,
        )
        if k8s_agent:
            console.print(f"  [green]✓[/green] Found {len(k8s_agent.mcp_servers)} MCP server(s) in Kubernetes (pods + CRDs)")
            agents.append(k8s_agent)
        else:
            console.print("  [dim]  k8s-mcp scan: no MCP pods/CRDs found (or kubectl not available)[/dim]")

    installed_agents: list[Agent] = []
    if not project_dir:
        # Installed-but-not-configured agents are ambient host signals, so
        # keep them out of explicitly project-scoped scans.
        discovered_types = {a.agent_type for a in agents}
        installed_agents = detect_installed_agents(discovered_types)
        for ia in installed_agents:
            console.print(f"  [dim]  {_display_label(ia.name)}: installed but not configured[/dim]")
        agents.extend(installed_agents)

    # Dynamic content-based discovery layer (opt-in)
    if dynamic:
        from pathlib import Path as _DynPath

        from agent_bom.discovery.dynamic import discover_dynamic, merge_discoveries

        console.print("\n  [bold cyan]🔎 Running dynamic discovery...[/bold cyan]")
        known_paths = {a.config_path for a in agents if a.config_path}
        dyn_result = discover_dynamic(
            root=_DynPath(project_search_dir) if project_search_dir else _DynPath.cwd(),
            max_depth=dynamic_max_depth,
            exclude_paths=known_paths,
        )
        if dyn_result.agents:
            console.print(
                f"  [green]✓[/green] Dynamic discovery found {len(dyn_result.agents)} additional config(s) "
                f"({dyn_result.scanned_paths} files scanned, {dyn_result.elapsed_ms:.0f}ms)"
            )
        agents = merge_discoveries(agents, dyn_result.agents)

    from agent_bom.discovery.identity import deduplicate_discovered_agents

    agents = deduplicate_discovered_agents(agents)
    configured = [a for a in agents if a.status == AgentStatus.CONFIGURED]
    if not configured and not installed_agents:
        console.print("  [yellow]No MCP configurations found.[/yellow]")
    else:
        total_servers = sum(len(a.mcp_servers) for a in configured)
        console.print(f"\n  [bold]Found {len(configured)} configured agent(s) with {total_servers} MCP server(s) total.[/bold]")
        if installed_agents:
            console.print(f"  [dim]{len(installed_agents)} additional agent(s) installed but not configured.[/dim]")

    return agents


if TYPE_CHECKING:
    from agent_bom.discovery.local_sources import discover_filesystem_mcps as discover_filesystem_mcps
    from agent_bom.discovery.platform_config import _CUSTOM_PARSERS as _CUSTOM_PARSERS
    from agent_bom.discovery.platform_config import _INSTALL_SIGNALS as _INSTALL_SIGNALS
    from agent_bom.discovery.platform_config import AGENT_BINARIES as AGENT_BINARIES
    from agent_bom.discovery.platform_config import PROJECT_CONFIG_FILES as PROJECT_CONFIG_FILES
    from agent_bom.discovery.platform_config import _find_binary as _find_binary
    from agent_bom.discovery.platform_config import _project_scope_path as _project_scope_path
    from agent_bom.discovery.platform_config import _read_text_no_symlink as _read_text_no_symlink
    from agent_bom.discovery.platform_config import get_all_discovery_paths as get_all_discovery_paths

_EXPORTS = {
    "AGENT_BINARIES": "agent_bom.discovery.platform_config",
    "PROJECT_CONFIG_FILES": "agent_bom.discovery.platform_config",
    "_CUSTOM_PARSERS": "agent_bom.discovery.platform_config",
    "_INSTALL_SIGNALS": "agent_bom.discovery.platform_config",
    "_project_scope_path": "agent_bom.discovery.platform_config",
    "get_all_discovery_paths": "agent_bom.discovery.platform_config",
    "_find_binary": "agent_bom.discovery.platform_config",
    "discover_filesystem_mcps": "agent_bom.discovery.local_sources",
    "_read_text_no_symlink": "agent_bom.discovery.platform_config",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
