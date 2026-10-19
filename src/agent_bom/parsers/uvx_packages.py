"""Uvx packages."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.core.settings import env_raw
from agent_bom.models import MCPServer, Package
from agent_bom.parsers.go_resolution import logger


def _normalize_python_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _resolve_uv_cached_version(name: str) -> tuple[str, Path] | None:
    """Return an exact package version from uv's local cache, if present."""
    cache_root = Path(env_raw("UV_CACHE_DIR") or Path.home() / ".cache" / "uv")
    if not cache_root.exists():
        return None

    wanted = _normalize_python_dist_name(name)
    matches: list[tuple[float, str, Path]] = []
    inspected = 0
    for metadata_path in cache_root.glob("archive-v*/**/*.dist-info/METADATA"):
        inspected += 1
        if inspected > 5000:
            break
        try:
            dist_info_name = metadata_path.parent.name.rsplit(".dist-info", 1)[0]
            candidate_name = dist_info_name.rsplit("-", 1)[0]
            if _normalize_python_dist_name(candidate_name) != wanted:
                continue
            metadata = metadata_path.read_text(encoding="utf-8", errors="replace")
            version = ""
            declared_name = ""
            for line in metadata.splitlines():
                if line.startswith("Name: "):
                    declared_name = line.removeprefix("Name: ").strip()
                elif line.startswith("Version: "):
                    version = line.removeprefix("Version: ").strip()
                if declared_name and version:
                    break
            if version and (not declared_name or _normalize_python_dist_name(declared_name) == wanted):
                matches.append((metadata_path.stat().st_mtime, version, metadata_path))
        except Exception as exc:
            logger.debug("Failed to inspect uv cache package metadata at %s: %s", metadata_path, exc)
    if not matches:
        return None
    _, version, path = max(matches, key=lambda item: item[0])
    return version, path


def _uvx_package_from_command(name: str, declared_version: str, server: MCPServer) -> Package:
    is_floating = declared_version in {"latest", "*"}
    cached = _resolve_uv_cached_version(name) if is_floating else None
    version = cached[0] if cached else declared_version
    pkg = Package(
        name=name,
        version=version,
        ecosystem="pypi",
        purl=f"pkg:pypi/{name}@{version}",
        is_direct=True,
    )
    pkg.declared_version = declared_version
    if not is_floating:
        pkg.resolved_version = version
        pkg.version_source = "command_pin"
        pkg.version_confidence = "exact"
        pkg.version_evidence = [{"type": "command_pin", "source_file": server.config_path or "", "parser": "uvx"}]
    elif cached:
        _, evidence_path = cached
        pkg.resolved_version = version
        pkg.version_source = "tool_cache"
        pkg.version_confidence = "high"
        pkg.version_resolved_at = datetime.now(timezone.utc).isoformat()
        pkg.version_evidence = [{"type": "tool_cache", "path": str(evidence_path), "parser": "uvx"}]
        pkg.floating_reference = True
        pkg.floating_reference_reason = "uvx command omitted an explicit package version"
    else:
        pkg.resolved_from_registry = True
        pkg.version_source = "registry_fallback"
        pkg.registry_version = declared_version
        pkg.floating_reference = True
        pkg.floating_reference_reason = "uvx command omitted an explicit package version"
    return pkg


def detect_uvx_package(server: MCPServer) -> list[Package]:
    """Extract package info from uvx/uv commands."""
    packages: list[Package] = []
    if server.command not in ("uvx", "uv"):
        return packages

    args = list(server.args)
    index = 0
    while index < len(args):
        arg = args[index]
        # ``uv tool run <pkg>`` stacks two sub-commands before the package.
        # Reading the token immediately after the FIRST one resolved
        # ``uv tool run flask==0.12.2`` to a package literally named "run".
        if arg in ("run", "tool"):
            index += 1
            continue
        if arg == "--from" and index + 1 < len(args):
            arg = args[index + 1]
        elif arg.startswith("-"):
            index += 1
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)(?:==(.+))?$", arg)
        if match:
            name = match.group(1)
            version = match.group(2) or "latest"
            packages.append(_uvx_package_from_command(name, version, server))
        break

    return packages
