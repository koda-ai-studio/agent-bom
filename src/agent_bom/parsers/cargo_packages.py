"""Cargo packages."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.cargo_lockfile import parse_cargo_lock
from agent_bom.parsers.go_resolution import _validate_https_url, logger

_CRATES_IO_URL = "https://crates.io"

_CARGO_UNRESOLVED_VERSIONS = frozenset({"*", "", "latest", "unknown"})


def resolve_cargo_version(
    crate_name: str,
    version: str,
    *,
    crates_io_url: str = _CRATES_IO_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Cargo crate version using the crates.io REST API.

    Queries ``https://crates.io/api/v1/crates/{crate_name}`` and returns
    the ``max_stable_version`` field, which is the latest non-pre-release
    version published for the crate.

    If *version* is already pinned (not ``"*"``, ``""``, ``"latest"`` or
    ``"unknown"``), it is returned immediately without any network call.

    Respects crates.io's rate-limit policy: sleeps 1 second when a network
    request is actually made.  Never raises — any error causes the original
    version string to be returned.

    Args:
        crate_name: Name of the Cargo crate (e.g. ``"serde"``).
        version: Current version string.  Pass ``"*"`` or ``""`` to trigger
            resolution.
        crates_io_url: Base URL of the crates.io API.  Must be HTTPS.
            Defaults to ``https://crates.io``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"1.0.196"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _CARGO_UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(crates_io_url, "crates_io_url")

    encoded_name = urllib.parse.quote(crate_name, safe="")
    api_url = f"{crates_io_url}/api/v1/crates/{encoded_name}"
    from agent_bom import __version__

    user_agent = f"agent-bom/{__version__} (github.com/msaad00/agent-bom)"

    try:
        from agent_bom.http_client import fetch_bytes

        raw_body = fetch_bytes(api_url, timeout=timeout, headers={"User-Agent": user_agent}).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original on failure
        logger.warning(
            "crates.io version resolution failed for %s — returning original version: %s",
            crate_name,
            exc,
        )
        return version
    finally:
        # Respect crates.io rate-limit policy: 1 req/sec
        time.sleep(1)

    try:
        data = json.loads(raw_body)
        crate_data = data.get("crate", {})
        resolved = (crate_data.get("max_stable_version") or "").strip()
        if resolved:
            return resolved
    except (ValueError, KeyError, AttributeError) as exc:
        logger.warning(
            "Failed to parse crates.io response for %s: %s",
            crate_name,
            exc,
        )

    return version


def _cargo_dep_version(spec: object, workspace_spec: object | None = None) -> Optional[str]:
    """Extract the declared version from a Cargo.toml dependency spec.

    Accepts the short form (``serde = "1.0"``) and the table form
    (``serde = { version = "1.0", features = [...] }``). Returns None for
    path/git/workspace deps that carry no concrete version requirement.
    """
    if isinstance(spec, str):
        return spec or None
    if isinstance(spec, dict):
        if spec.get("workspace") is True:
            return _cargo_dep_version(workspace_spec)
        if "path" in spec or "git" in spec:
            return None
        version = spec.get("version")
        return version if isinstance(version, str) and version else None
    return None


def _cargo_dependency_tables(data: dict) -> list[tuple[dict, bool]]:
    """Return Cargo dependency tables with direct/development attribution."""

    tables: list[tuple[dict, bool]] = []
    for table, direct in (("dependencies", True), ("dev-dependencies", False), ("build-dependencies", False)):
        deps = data.get(table)
        if isinstance(deps, dict):
            tables.append((deps, direct))

    targets = data.get("target")
    if isinstance(targets, dict):
        for target_cfg in targets.values():
            if not isinstance(target_cfg, dict):
                continue
            for table, direct in (("dependencies", True), ("dev-dependencies", False), ("build-dependencies", False)):
                deps = target_cfg.get(table)
                if isinstance(deps, dict):
                    tables.append((deps, direct))
    return tables


def _parse_cargo_toml(cargo_toml: Path) -> list[Package]:
    """Parse declared dependencies from Cargo.toml (manifest-only fallback).

    Used when a Rust project has no Cargo.lock. Versions are SemVer *requirements*
    (e.g. ``"1.0"``, ``"^1.2"``) rather than the exact pins a lockfile carries, so
    coverage is approximate — but vastly better than the previous silent zero.
    """
    try:
        import tomllib

        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        logger.debug("Could not parse Cargo.toml at %s: %s", cargo_toml, exc)
        record_manifest_parse_warning(
            ecosystem="cargo",
            path=str(cargo_toml),
            detail="Cargo.toml could not be read or parsed; Cargo dependencies were not scanned",
        )
        return []

    pkgs: list[Package] = []
    seen: set[str] = set()
    workspace = data.get("workspace")
    workspace_deps = workspace.get("dependencies") if isinstance(workspace, dict) else None
    if not isinstance(workspace_deps, dict):
        workspace_deps = {}

    for deps, direct in _cargo_dependency_tables(data):
        for name, spec in deps.items():
            version = _cargo_dep_version(spec, workspace_deps.get(name))
            if not version or name in seen:
                continue
            seen.add(name)
            pkgs.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="cargo",
                    purl=f"pkg:cargo/{name}@{version}",
                    is_direct=direct,
                    version_source="manifest",
                )
            )
    return pkgs


def parse_cargo_packages(directory: Path, *, resolve_versions: bool = False) -> list[Package]:
    """Parse packages from Cargo.lock, falling back to Cargo.toml.

    Args:
        directory: Project directory containing ``Cargo.lock`` and/or ``Cargo.toml``.
        resolve_versions: When ``True``, packages with unresolved versions
            (``"*"``, ``""``, ``"latest"`` or ``"unknown"``) are queried
            against the crates.io REST API to obtain their latest stable
            version.  Adds a 1-second sleep between requests to respect
            crates.io rate limits.  Default ``False`` — no network calls.
    """
    cargo_packages: list[Package] = []
    cargo_lock = directory / "Cargo.lock"

    if cargo_lock.exists():
        cargo_packages = parse_cargo_lock(directory)
    elif (directory / "Cargo.toml").exists():
        # Manifest-only project (no lockfile): parse declared deps so the whole
        # cargo ecosystem isn't silently missed.
        cargo_packages = _parse_cargo_toml(directory / "Cargo.toml")

    if resolve_versions:
        for pkg in cargo_packages:
            if pkg.version in _CARGO_UNRESOLVED_VERSIONS:
                cargo_resolved = resolve_cargo_version(pkg.name, pkg.version)
                if cargo_resolved != pkg.version:
                    pkg.version = cargo_resolved
                    pkg.purl = f"pkg:cargo/{pkg.name}@{cargo_resolved}"
                    pkg.version_source = "registry_fallback"

    return cargo_packages
