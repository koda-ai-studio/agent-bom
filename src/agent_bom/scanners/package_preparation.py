"""Package identity, installed-version resolution and scan eligibility."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.models import Package
from agent_bom.package_utils import canonical_package_identity, normalize_package_name, package_purl
from agent_bom.scanners import cpython_advisory as runtime_cve
from agent_bom.scanners.package_matching import _emit_scan_warning as _emit_scan_warning
from agent_bom.scanners.package_matching import _scanners_patchable
from agent_bom.scanners.package_versions import is_unresolved_package as _is_unresolved_package
from agent_bom.scanners.package_versions import is_unresolved_version as _is_unresolved_version
from agent_bom.scanners.scan_options import _logger, _package_db_key
from agent_bom.scanners.state import _bump_scan_perf, record_coverage_warning, reset_scan_performance, reset_scan_warnings_only


def _target_venv_python(project_dir: str | None) -> str | None:
    """Return a Python interpreter inside the TARGET project's virtualenv.

    Local pip resolution must reflect what is installed in the *target* project,
    not the scanner host. Only a virtualenv shipped with the target counts; when
    none exists we resolve nothing rather than stamping a host version.
    """
    if not project_dir:
        return None
    root = Path(project_dir)
    for rel in (
        (".venv", "bin", "python"),
        ("venv", "bin", "python"),
        (".venv", "Scripts", "python.exe"),
        ("venv", "Scripts", "python.exe"),
    ):
        candidate = root.joinpath(*rel)
        if candidate.exists():
            return str(candidate)
    return None


_NON_OSV_ECOSYSTEMS: frozenset[str] = frozenset(
    {
        "docker",  # Image stubs from MCP configs / docker-compose / running containers
        "container",  # GPU infra image refs (cuda-toolkit, cudnn)
        "container-image",  # CoreWeave / Nebius pod images
        "github-action",  # Remote GitHub Action repository references
        "github-action-workflow",  # Remote reusable-workflow references
        "ollama",  # Ollama model names — no OSV advisory DB
        "smithery",  # Smithery MCP marketplace stubs
        "mcp-registry",  # MCP Registry stubs
        "azure-runtime",  # Azure Functions / ACA runtime images
        "nebius-ai-studio",  # Nebius AI Studio model artifacts
        "nebius-compute-image",  # Nebius compute node images
        "sast",  # SAST findings represented as packages
        "unknown",  # Packages with unresolvable ecosystem (e.g. --sbom ingest)
    }
)


def _warn_unresolved_packages(packages: list[Package]) -> None:
    if not packages:
        return
    names = ", ".join(f"{p.name}@{p.version}" for p in packages[:10])
    suffix = f" (+{len(packages) - 10} more)" if len(packages) > 10 else ""
    _scanners_patchable("console").print(f"  [yellow]⚠[/yellow] {len(packages)} package(s) skipped (unresolved version): {names}{suffix}")
    _logger.warning(
        "Skipped %d package(s) with unresolved versions: %s",
        len(packages),
        names + suffix,
    )
    _emit_scan_warning(f"{len(packages)} package(s) skipped due to unresolved versions")
    record_coverage_warning(
        {
            "kind": "package_version_gap",
            "release": "unresolved-package-versions",
            "reason": "unresolved_version",
            "package_count": len(packages),
            "detail": "Package versions are unresolved or invalid; supply resolved lockfiles or valid release versions.",
        }
    )


def _strip_extras(name: str) -> str:
    """Strip pip extras notation: ``requests[security]`` → ``requests``."""
    import re as _re

    return _re.sub(r"\[.*?\]$", "", name)


def deduplicate_packages(packages: list) -> list:
    """Remove duplicate packages across discovery sources.

    Deduplicates by (ecosystem, normalized_name, version) fingerprint.
    When duplicates exist, the first occurrence is kept (preserves source ordering).

    This prevents redundant OSV API calls and duplicate vulnerability findings
    when the same package is discovered from multiple sources (local, K8s, cloud).

    Args:
        packages: List of Package objects from one or more discovery sources.

    Returns:
        Deduplicated list, preserving first-seen order.
    """
    seen: set[tuple[str, ...]] = set()
    result = []
    for pkg in packages:
        # Use normalized name for dedup (PEP 503: torch == Torch == pytorch)
        name = getattr(pkg, "name", "") or ""
        ecosystem = getattr(pkg, "ecosystem", "") or ""
        version = getattr(pkg, "version", "") or ""
        key = (*canonical_package_identity(name, version, ecosystem, getattr(pkg, "purl", None)), runtime_cve.runtime_assessment_key(pkg))
        if key not in seen:
            seen.add(key)
            result.append(pkg)
    return result


def _prepare_packages(packages: list[Package]) -> list[Package]:
    """Deduplicate across discovery sources (local, K8s, cloud) and normalize names for matching."""
    original_count = len(packages)
    packages = deduplicate_packages(packages)
    deduped = original_count - len(packages)
    reset_scan_performance()
    _bump_scan_perf("packages_seen", original_count)
    if deduped > 0:
        _bump_scan_perf("packages_deduplicated", deduped)
        _logger.info("Deduplicated %d duplicate packages (kept %d unique)", deduped, len(packages))

    # Normalize package names for consistent matching (PEP 503 for PyPI)
    # and strip pip extras notation (OSV doesn't understand extras)
    for pkg in packages:
        if pkg.ecosystem.lower() == "pypi":
            if "[" in pkg.name:
                pkg.name = _strip_extras(pkg.name)
            pkg.name = normalize_package_name(pkg.name, pkg.ecosystem)
    return packages


async def _scan_runtime_packages(packages: list[Package], offline: bool) -> tuple[list[Package], int]:
    """Scan CPython runtimes separately; return the remaining packages and runtime vuln count."""
    reset_scan_warnings_only()
    runtime_packages = [package for package in packages if runtime_cve.is_cpython_runtime(package)]
    runtime_count = await runtime_cve.scan_cpython_runtimes(runtime_packages, offline=offline)
    packages = [package for package in packages if not runtime_cve.is_cpython_runtime(package)]
    try:
        from agent_bom.resolver import reset_performance_stats as _reset_resolver_performance

        _reset_resolver_performance()
    except Exception:  # noqa: BLE001
        pass
    return packages, runtime_count


def _apply_installed_versions(packages: list[Package], installed_version: Any) -> int:
    resolved = 0
    for pkg in packages:
        installed_ver = installed_version(pkg)
        if installed_ver:
            pkg.version = installed_ver
            pkg.purl = package_purl(pkg.name, installed_ver, pkg.ecosystem)
            pkg.version_source = "installed"
            resolved += 1
    return resolved


def _resolve_local_versions(unresolved: list[Package], target_dir: str | None) -> None:
    """Resolve versions from packages installed in the target project (``-p``), never the scanner host."""
    try:
        from agent_bom.resolvers.runtime_resolver import resolve_go_versions, resolve_npm_versions, resolve_pip_versions

        local_resolved = 0
        # Resolve pip packages from the target project's virtualenv only.
        pip_unresolved = [p for p in unresolved if p.ecosystem.lower() == "pypi"]
        venv_python = _target_venv_python(target_dir)
        if pip_unresolved and venv_python:
            pip_versions = resolve_pip_versions(venv_python)
            local_resolved += _apply_installed_versions(
                pip_unresolved,
                lambda pkg: (
                    pip_versions.get(pkg.name.lower())
                    or pip_versions.get(pkg.name.lower().replace("-", "_"))
                    or pip_versions.get(pkg.name.lower().replace("_", "-"))
                ),
            )

        # Resolve npm and Go packages from the target project directory.
        for local_ecosystem, resolve_local_versions in (("npm", resolve_npm_versions), ("go", resolve_go_versions)):
            eco_unresolved = [p for p in unresolved if p.ecosystem.lower() == local_ecosystem]
            if not (eco_unresolved and target_dir):
                continue
            local_versions = resolve_local_versions(Path(target_dir))
            local_resolved += _apply_installed_versions(eco_unresolved, lambda pkg: local_versions.get(pkg.name))

        if local_resolved:
            _scanners_patchable("console").print(f"  [green]✓[/green] Resolved {local_resolved} package version(s) from local install")
    except Exception as exc:
        _logger.debug("Local version resolution failed: %s", exc)


async def _resolve_registry_versions(packages: list[Package], offline: bool) -> None:
    still_unresolved = [p for p in packages if _is_unresolved_package(p) and p.ecosystem.lower() in ("npm", "pypi", "conda")]
    if still_unresolved and not offline:
        try:
            from agent_bom.resolver import resolve_all_versions

            resolved_count = await resolve_all_versions(still_unresolved)
            if resolved_count:
                # Mark these as registry-resolved so output shows confidence
                for pkg in still_unresolved:
                    if not _is_unresolved_version(pkg.version):
                        pkg.version_source = "registry_fallback"
                _scanners_patchable("console").print(f"  [green]✓[/green] Auto-resolved {resolved_count} package version(s) from registry")
        except Exception as exc:
            _logger.warning("Version resolution failed for %d package(s): %s", len(still_unresolved), exc)
            _scanners_patchable("console").print(f"  [yellow]⚠[/yellow] Version resolution skipped: {exc}")
            _emit_scan_warning("version resolution failed for one or more packages")
    elif still_unresolved and offline:
        _logger.info("Offline mode: skipping registry version resolution for %d package(s)", len(still_unresolved))


async def _expand_transitive_packages(packages: list[Package]) -> list[Package]:
    transitive_ecosystems = {"npm", "pypi", "go"}
    eligible = [p for p in packages if p.ecosystem.lower() in transitive_ecosystems]
    if eligible:
        try:
            from agent_bom.transitive import resolve_transitive_dependencies

            _logger.info("Resolving transitive dependencies for %d package(s)...", len(eligible))
            transitive_pkgs = await resolve_transitive_dependencies(eligible)
            if transitive_pkgs:
                existing_keys = {_package_db_key(p) for p in packages}
                new_pkgs = [p for p in transitive_pkgs if _package_db_key(p) not in existing_keys]
                if new_pkgs:
                    packages = packages + new_pkgs
                    packages = deduplicate_packages(packages)
                    _scanners_patchable("console").print(
                        f"  [cyan]→[/cyan] Transitive resolution: {len(new_pkgs)} additional package(s) queued"
                    )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Transitive resolution failed, scanning direct dependencies only: %s", exc)
            _emit_scan_warning("transitive dependency resolution failed")
    return packages


def _select_scannable_packages(packages: list[Package]) -> list[Package]:
    # Inventory-only ecosystems have no advisory sources. Exclude them from local DB coverage
    # accounting and live OSV queries so offline scans do not report them as incomplete SCA.
    non_osv_packages = [p for p in packages if p.ecosystem.lower() in _NON_OSV_ECOSYSTEMS]
    for package in non_osv_packages:
        _logger.debug(
            "Skipping package %s/%s: ecosystem %r is not OSV-queryable (handled by other pipeline)",
            package.ecosystem,
            package.name,
            package.ecosystem,
        )
    if non_osv_packages:
        _bump_scan_perf("skipped_non_osv_ecosystems", len(non_osv_packages))
    scannable = [p for p in packages if not _is_unresolved_package(p) and p.ecosystem.lower() not in _NON_OSV_ECOSYSTEMS]

    # Warn about packages that could not be resolved — no silent failures
    still_unresolved = [p for p in packages if _is_unresolved_package(p) and p.ecosystem.lower() not in _NON_OSV_ECOSYSTEMS]
    _warn_unresolved_packages(still_unresolved)
    return scannable
