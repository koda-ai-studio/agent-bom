"""Shared scan pipeline for the MCP server.

This module keeps the public ``agent_bom.mcp_server`` wrapper surface stable
while moving the discovery + scan pipeline out of the monolith.
"""

from __future__ import annotations

import logging
import shlex
from contextvars import ContextVar
from pathlib import Path
from typing import Optional

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.mcp_errors import (
    CODE_VALIDATION_INVALID_ECOSYSTEM,
    CODE_VALIDATION_INVALID_IMAGE_REF,
    CODE_VALIDATION_INVALID_PATH,
)
from agent_bom.security import sanitize_error  # noqa: F401 — kept for downstream importers


class McpScanValidationError(ValueError):
    """A scan input failed validation (e.g. a path outside the sandbox).

    Raised by :func:`run_scan_pipeline` instead of returning an error payload so
    the many call-sites that unpack a 4-tuple do not crash with "too many values
    to unpack (expected 4)" and tools surface a clean, structured error. It
    subclasses ``ValueError`` so existing ``except ValueError`` / ``except
    Exception`` handlers still catch it; ``code`` carries the machine-readable
    validation code.
    """

    def __init__(self, code: str, message: Exception | str, *, argument: str | None = None) -> None:
        self.code = code
        self.argument = argument
        text = message if isinstance(message, str) else sanitize_error(message)
        suffix = f" (argument: {argument})" if argument else ""
        super().__init__(f"{code}: {text}{suffix}")


logger = logging.getLogger(__name__)


PACKAGE_SPEC_DISCOVERY_SOURCE = "mcp_scan_package"

# Launcher token -> the ecosystem that launcher installs from. A spec that names
# its launcher is not a guess; the ecosystem follows from the command.
_LAUNCHER_ECOSYSTEMS = {
    "npx": "npm",
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bunx": "npm",
    "uvx": "pypi",
    "uv": "pypi",
    "pip": "pypi",
    "pip3": "pypi",
    "pipx": "pypi",
}

# Sub-commands that sit between the launcher and the package it installs
# (``npm exec <pkg>``, ``uv tool run <pkg>``, ``pip install <pkg>``). Left in
# place they were parsed AS the package: ``uv tool run flask==0.12.2`` resolved
# to a PyPI package literally named ``run``.
_LAUNCHER_SUBCOMMANDS = {"dlx", "exec", "run", "tool", "install"}

# The two ecosystems a synthetic launcher command can express; every other
# ecosystem names its package directly on the synthetic server instead.
_ECOSYSTEM_LAUNCHERS = {"npm": "npx", "pypi": "uvx"}

# PEP 440 / PEP 508 version specifiers. An npm spec never contains these, so
# their presence identifies a Python requirement even with no launcher token.
_PEP508_OPERATORS = ("===", "==", "~=", "!=", ">=", "<=", ">", "<")


def _package_spec_agent(package_spec: str, *, ecosystem: str | None = None):
    """Build a synthetic MCP inventory entry from a direct package command.

    Returns ``(agent, warnings)``. ``warnings`` is non-empty whenever the
    ecosystem had to be *assumed*: the caller named neither a launcher nor an
    ``ecosystem``, so the result is reported as an assumption rather than
    presented as fact.

    Previously any unrecognized first token was forced to ``npx``, which scanned
    ``flask==0.12.2`` as an npm package and extracted nothing — a clean-looking
    AI-BOM for a package with known CVEs.
    """
    from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    tokens = shlex.split(package_spec)
    if not tokens:
        raise ValueError("package must not be empty")

    requested: str | None = None
    if ecosystem is not None and str(ecosystem).strip():
        requested = str(ecosystem).strip().lower()
        if requested not in SUPPORTED_PACKAGE_ECOSYSTEM_SET:
            raise ValueError(f"Invalid ecosystem: {ecosystem!r}. Valid: {', '.join(sorted(SUPPORTED_PACKAGE_ECOSYSTEM_SET))}")

    launcher = tokens[0] if tokens[0] in _LAUNCHER_ECOSYSTEMS else None
    args = tokens[1:] if launcher is not None else list(tokens)
    while args and args[0] in _LAUNCHER_SUBCOMMANDS:
        args = args[1:]

    warnings: list[str] = []
    if requested is not None:
        resolved = requested
    elif launcher is not None:
        resolved = _LAUNCHER_ECOSYSTEMS[launcher]
    elif any(operator in package_spec for operator in _PEP508_OPERATORS):
        resolved = "pypi"
    else:
        resolved = "npm"
        warnings.append(
            f"'{package_spec}' names neither a launcher nor an ecosystem; assumed the "
            f"{resolved} ecosystem. Pass ecosystem='pypi' (or cargo/maven/go/...), or "
            "prefix the launcher (e.g. 'uvx <spec>'), to scan a different ecosystem."
        )

    command = _ECOSYSTEM_LAUNCHERS.get(resolved, "")
    packages: list[Package] = []
    if not command:
        # cargo/maven/go/... have no launcher spelling the scanner understands,
        # so name the package on the server directly instead of round-tripping
        # it through a command line that would resolve to the wrong ecosystem.
        from agent_bom.mcp_tools.scanning import normalize_check_package_spec

        name, version = normalize_check_package_spec(" ".join(args) if args else package_spec)
        packages = [Package(name=name, version=version, ecosystem=resolved)]

    server = MCPServer(
        name=f"package:{' '.join([command, *args]).strip()}",
        command=command,
        args=args,
        env={},
        transport=TransportType.STDIO if command else TransportType.UNKNOWN,
        config_path="mcp-scan-package",
        discovery_sources=[PACKAGE_SPEC_DISCOVERY_SOURCE],
        packages=packages,
    )
    return (
        Agent(
            name=f"package:{package_spec}",
            agent_type=AgentType.CUSTOM,
            config_path="mcp-scan-package",
            mcp_servers=[server],
        ),
        warnings,
    )


def package_spec_extracted_count(agents) -> int:
    """Count packages extracted from synthetic ``package=`` scan targets.

    The fail-closed guard reads this: a package spec that resolves to zero
    packages must never be presented as a completed clean scan.
    """
    return sum(
        len(server.packages)
        for agent in agents
        for server in agent.mcp_servers
        if PACKAGE_SPEC_DISCOVERY_SOURCE in (server.discovery_sources or [])
    )


def unresolved_package_spec_warning(package_spec: str) -> str:
    """The single wording for "this package spec produced no evidence"."""
    return (
        f"No packages could be resolved from package spec '{package_spec}'; the scan is "
        "incomplete and its empty result is NOT evidence that the package is clean. "
        "Pass an explicit ecosystem (e.g. ecosystem='pypi') or a launcher-prefixed "
        "spec (e.g. 'uvx <spec>')."
    )


_REPO_TREE_INVENTORY: ContextVar[Optional[dict]] = ContextVar("mcp_repo_tree_inventory", default=None)


def consume_repo_tree_inventory() -> Optional[dict]:
    """Return and clear the repo-tree side inventory (secrets, AST, ...) of the last pipeline run."""
    inventory = _REPO_TREE_INVENTORY.get()
    _REPO_TREE_INVENTORY.set(None)
    return inventory


def _scan_config_path_statically(config_path: str, agents: list, warnings: list[str], scan_sources: list[str], *, offline: bool) -> None:
    """Repo-tree, Python-agent, Terraform and GitHub Actions passes over an explicit target."""
    try:
        from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree
        from agent_bom.github_actions import scan_github_actions
        from agent_bom.python_agents import scan_python_agents
        from agent_bom.terraform import scan_terraform_dir

        tree = scan_cloned_repo_tree(config_path, agents=agents, warnings=warnings, offline=offline)
        _REPO_TREE_INVENTORY.set(tree.ai_inventory_data or None)
        scan_sources.append("repo_tree")
        # IaC is scanned opportunistically here, so a tree without .tf files is not a warning.
        passes = (
            ("python_agents", lambda: scan_python_agents(config_path)),
            ("terraform", lambda: scan_terraform_dir(config_path, report_missing=False)),
            ("github_actions", lambda: scan_github_actions(config_path)),
        )
        for source, run_pass in passes:
            found, found_warnings = run_pass()
            agents.extend(found)
            warnings.extend(found_warnings)
            if found:
                scan_sources.append(source)
    except Exception as exc:
        msg = f"Repo static scan failed for {config_path}: {sanitize_error(exc)}"
        logger.warning(msg)
        warnings.append(msg)


async def run_scan_pipeline(
    *,
    safe_path,
    config_path: Optional[str] = None,
    image: Optional[str] = None,
    sbom_path: Optional[str] = None,
    package: Optional[str] = None,
    enrich: bool = False,
    transitive: bool = False,
    offline: bool = False,
    ecosystem: Optional[str] = None,
    no_discover: bool = False,
):
    """Run discovery -> extraction -> scanning and return agents + findings."""
    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import ScanOptions, scan_agents, scan_agents_with_enrichment

    warnings: list[str] = []
    scan_sources: list[str] = []
    _REPO_TREE_INVENTORY.set(None)

    if config_path:
        try:
            config_path = str(safe_path(config_path))
        except ValueError as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="config_path") from exc

    if sbom_path:
        try:
            sbom_path = str(safe_path(sbom_path))
        except ValueError as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="sbom_path") from exc

    if image:
        try:
            from agent_bom.security import validate_image_ref

            validate_image_ref(image)
        except Exception as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_IMAGE_REF, exc, argument="image") from exc

    # Match the CLI's deterministic CI mode: no_discover skips only machine-wide
    # discovery. An explicit config_path is an artifact and is still scanned
    # with project-scoped discovery, exactly like `--no-discover --config-dir`.
    # Machine-wide discovery reads host data, so shared transports refuse it.
    if config_path:
        agents = discover_all(project_dir=config_path)
    else:
        if not no_discover:
            from agent_bom.mcp_tools.host_local import host_discovery_allowed

            no_discover = not host_discovery_allowed(explicit_target=bool(image or sbom_path or package), warnings=warnings)
        agents = [] if no_discover else discover_all()
    if agents:
        scan_sources.append("agent_discovery")

    if config_path:
        _scan_config_path_statically(config_path, agents, warnings, scan_sources, offline=offline)

    if package:
        try:
            package_agent, package_warnings = _package_spec_agent(package, ecosystem=ecosystem)
        except ValueError as exc:
            code = CODE_VALIDATION_INVALID_ECOSYSTEM if "ecosystem" in str(exc).lower() else CODE_VALIDATION_INVALID_PATH
            argument = "ecosystem" if code == CODE_VALIDATION_INVALID_ECOSYSTEM else "package"
            raise McpScanValidationError(code, exc, argument=argument) from exc
        agents.append(package_agent)
        warnings.extend(package_warnings)
        scan_sources.append("mcp_package")

    if image:
        try:
            from agent_bom.image import scan_image as _scan_image
            from agent_bom.models import ServerSurface

            img_packages, _strategy = _scan_image(image)
            if img_packages:
                img_server = MCPServer(
                    name=f"image:{image}",
                    command="",
                    args=[],
                    env={},
                    transport=TransportType.UNKNOWN,
                    packages=img_packages,
                    surface=ServerSurface.CONTAINER_IMAGE,
                )
                agents.append(
                    Agent(
                        name=f"image:{image}",
                        agent_type=AgentType.CUSTOM,
                        config_path="",
                        mcp_servers=[img_server],
                    )
                )
                scan_sources.append("image")
        except Exception as exc:
            msg = f"Image scan failed for {image}: {sanitize_error(exc)}"
            logger.warning(msg)
            warnings.append(msg)

    if sbom_path:
        try:
            sbom_file = Path(sbom_path)
            if sbom_file.exists() and sbom_file.stat().st_size > _MAX_FILE_SIZE:
                msg = f"SBOM file too large ({sbom_file.stat().st_size} bytes, max {_MAX_FILE_SIZE})"
                raise ValueError(msg)
            else:
                from agent_bom.parsers.sbom_context import load_sbom_agents

                sbom_agents, _fmt = load_sbom_agents(sbom_path)
                agents.extend(sbom_agents)
                scan_sources.append("sbom")
        except Exception as exc:
            raise McpScanValidationError(CODE_VALIDATION_INVALID_PATH, exc, argument="sbom_path") from exc

    if not agents:
        return [], [], warnings, scan_sources

    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)
            if offline:
                for pkg in server.packages:
                    if pkg.floating_reference and pkg.declared_version in {"latest", "*"}:
                        warnings.append(
                            f"{pkg.name} uses a floating package reference; pass {pkg.name}@version "
                            "or set offline=false for registry-backed resolution."
                        )

    if package and package_spec_extracted_count(agents) == 0:
        # Fail closed: a package spec the extractor could not resolve yields no
        # packages and therefore no findings. Reporting that as a clean scan is
        # a wrong answer, so say the scan is incomplete instead.
        warnings.append(unresolved_package_spec_warning(package))

    if enrich and not offline:
        blast_radii = await scan_agents_with_enrichment(agents, options=ScanOptions(offline=offline))
    else:
        blast_radii = await scan_agents(agents, options=ScanOptions(offline=offline))
    return agents, blast_radii, warnings, scan_sources
