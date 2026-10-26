"""Go, Maven, Cargo, Gradle, conda, and uvx package parsers.

Parses go.mod/go.sum, pom.xml, Cargo.lock, build.gradle/build.gradle.kts/
libs.versions.toml/gradle.lockfile, environment.yml/conda-lock.yml,
and detects packages from uvx/uv commands.
"""

from __future__ import annotations

import re
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.package_utils import package_purl
from agent_bom.parsers.go_resolution import _UNRESOLVED_VERSIONS as _UNRESOLVED_VERSIONS
from agent_bom.parsers.go_resolution import logger as logger
from agent_bom.parsers.go_resolution import resolve_go_version as resolve_go_version
from agent_bom.parsers.go_resolution import verify_go_checksums as verify_go_checksums
from agent_bom.parsers.gradle_packages import parse_gradle_packages as parse_gradle_packages

# Versions that need resolution via the Go module proxy

# Versions that require Maven Central resolution

# Versions that require crates.io resolution


_GO_REPLACE_BLOCK_RE = re.compile(r"^replace[ \t]*\(([^)]*)\)", re.MULTILINE)
_GO_REPLACE_SINGLE_RE = re.compile(r"^replace[ \t]+([^(\s][^\n]*)$", re.MULTILINE)
_GO_REPLACE_SPEC_RE = re.compile(r"^(\S+)(?:[ \t]+\S+)?[ \t]+=>[ \t]+(\S+)(?:[ \t]+(\S+))?$")


def _go_replace_directives(content: str) -> dict[str, tuple[str, str]]:
    """``old -> (new, version)``; a local-path replacement has an empty version."""
    specs = [line for block in _GO_REPLACE_BLOCK_RE.finditer(content) for line in block.group(1).splitlines()]
    specs.extend(match.group(1) for match in _GO_REPLACE_SINGLE_RE.finditer(content))
    replacements: dict[str, tuple[str, str]] = {}
    for spec in specs:
        match = _GO_REPLACE_SPEC_RE.match(spec.split("//", 1)[0].strip())
        if match:
            replacements[match.group(1)] = (match.group(2), match.group(3) or "")
    return replacements


def _parse_go_mod_requires(
    go_mod: Path,
) -> tuple[dict[str, str], dict[str, str], dict[str, tuple[str, str]]]:
    """Parse go.mod and return (direct, indirect, replace_map).

    Returns:
        direct: {module_path: version} for direct requires
        indirect: {module_path: version} for ``// indirect`` requires
        replace_map: {old_module: (new_module, new_version)} for replace directives
    """
    direct: dict[str, str] = {}
    indirect: dict[str, str] = {}
    replace_map: dict[str, tuple[str, str]] = {}

    if not go_mod.exists():
        return direct, indirect, replace_map

    try:
        content = go_mod.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Could not read go.mod at %s: %s", go_mod, exc)
        record_manifest_parse_warning(
            ecosystem="go",
            path=str(go_mod),
            detail="go.mod could not be read; Go dependencies were not scanned",
        )
        return direct, indirect, replace_map

    block_re = re.compile(r"require\s*\(([^)]+)\)", re.DOTALL)
    # Horizontal-whitespace only between tokens: ``\s`` also matches newlines, so
    # the old pattern matched the block opener ``require (`` and captured ``(`` as
    # the module + the next dependency line as its version — a phantom package
    # that, offline, was treated as DB-uncovered and silently dropped the whole
    # report. ``[ \t]+`` keeps the match on one line and skips the block opener.
    single_re = re.compile(r"^require[ \t]+(\S+)[ \t]+(\S+)([^\n]*)$", re.MULTILINE)

    # Block-style: require ( ... )
    for block in block_re.finditer(content):
        for line in block.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            is_indirect = "// indirect" in line
            clean = line.split("//")[0].strip()
            parts = clean.split()
            if len(parts) >= 2:
                mod, ver = parts[0], parts[1]
                (indirect if is_indirect else direct)[mod] = ver

    # Single-line: require module version [// indirect]
    for m in single_re.finditer(content):
        mod, ver, rest = m.group(1), m.group(2), m.group(3)
        (indirect if "indirect" in rest else direct)[mod] = ver

    replace_map.update(_go_replace_directives(content))

    return direct, indirect, replace_map


def parse_go_workspace(directory: Path) -> list[Package]:
    """Parse go.work for workspace module paths, then parse each module's go.mod.

    Supports Go 1.18+ multi-module workspaces.  Reads ``use`` directives from
    ``go.work`` and calls :func:`parse_go_packages` for each referenced module
    directory.  Deduplicates by ``(name, version)``; direct dependencies take
    priority over indirect when the same module appears in multiple modules.

    Args:
        directory: Directory containing the ``go.work`` file.

    Returns:
        Combined list of :class:`~agent_bom.models.Package` objects from all
        workspace modules.  Returns an empty list if ``go.work`` does not exist.
    """
    go_work = directory / "go.work"
    if not go_work.exists():
        return []

    try:
        content = go_work.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Could not read go.work at %s: %s", go_work, exc)
        record_manifest_parse_warning(
            ecosystem="go",
            path=str(go_work),
            detail="go.work could not be read; Go workspace dependencies were not scanned",
        )
        return []

    # Parse "use ./module_path" directives (single-line and block forms)
    module_dirs: list[Path] = []

    # Block-style: use ( ... )
    block_re = re.compile(r"use\s*\(([^)]+)\)", re.DOTALL)
    for block in block_re.finditer(content):
        for raw in block.group(1).splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("//"):
                module_dirs.append(directory / raw)

    # Single-line: use ./path
    single_re = re.compile(r"^use\s+(\S+)", re.MULTILINE)
    for m in single_re.finditer(content):
        # Avoid double-counting entries already captured by block form
        candidate = directory / m.group(1)
        if candidate not in module_dirs:
            module_dirs.append(candidate)

    if not module_dirs:
        return []

    # Parse each module and merge; prefer direct over indirect for duplicates
    seen_direct: dict[tuple[str, str], Package] = {}
    seen_indirect: dict[tuple[str, str], Package] = {}

    for mod_dir in module_dirs:
        for pkg in parse_go_packages(mod_dir):
            key = (pkg.name, pkg.version)
            if pkg.is_direct:
                seen_direct[key] = pkg
            else:
                seen_indirect.setdefault(key, pkg)

    # Merge: direct wins over indirect
    merged: dict[tuple[str, str], Package] = {**seen_indirect, **seen_direct}
    return list(merged.values())


def parse_go_packages(
    directory: Path,
    *,
    verify_checksums: bool = True,
    resolve_versions: bool = False,
) -> list[Package]:
    """Parse packages from go.mod and go.sum.

    If a ``go.work`` workspace file is present in *directory*, delegates to
    :func:`parse_go_workspace` to handle multi-module workspaces (Go 1.18+).

    Otherwise reads go.mod to correctly distinguish direct from indirect
    (transitive) dependencies and to apply ``replace`` directives.  Falls back
    to go.sum only when go.mod is absent, preserving unknown directness.

    Args:
        directory: Project root containing ``go.mod`` / ``go.sum``.
        verify_checksums: When ``True`` (default), compares go.sum hashes
            against the Go checksum database (``sum.golang.org``).  Any
            module whose hash does not match is flagged with
            ``is_malicious=True`` and an explanatory ``malicious_reason``.
            Requires outbound HTTPS access to ``sum.golang.org``.
        resolve_versions: When ``True``, unpinned versions (``"latest"``,
            ``"(devel)"``, ``""`` or ``"unknown"``) are resolved via the Go
            module proxy (``proxy.golang.org``).  Defaults to ``False`` to
            avoid network calls in pure parse mode — opt-in explicitly when
            version accuracy is required.
    """
    # Workspace mode takes priority
    go_work = directory / "go.work"
    if go_work.exists():
        return parse_go_workspace(directory)

    go_mod = directory / "go.mod"
    go_sum = directory / "go.sum"

    if not go_mod.exists() and not go_sum.exists():
        return []

    direct, indirect_mods, replace_map = _parse_go_mod_requires(go_mod)

    # Build combined module→(version, is_direct) map with replace applied
    all_mods: dict[str, tuple[str, bool]] = {}
    for source_map, is_direct in ((direct, True), (indirect_mods, False)):
        for mod, ver in source_map.items():
            target, target_ver = replace_map.get(mod, (mod, ver))
            if target_ver:
                all_mods[target] = (target_ver, is_direct)

    if all_mods:
        packages = []
        for mod, (ver, is_direct) in all_mods.items():
            # Optionally resolve unpinned versions via GOPROXY
            if resolve_versions and ver in _UNRESOLVED_VERSIONS:
                resolved = resolve_go_version(mod, ver)
                if resolved != ver:
                    ver = resolved
                    logger.debug("Resolved %s → %s via GOPROXY", mod, ver)

            clean_ver = ver[1:] if ver.startswith("v") else ver
            pkg = Package(
                name=mod,
                version=clean_ver,
                ecosystem="go",
                purl=f"pkg:golang/{mod}@{ver}",
                is_direct=is_direct,
                version_source="manifest",
                version_evidence=[{"type": "manifest", "source_file": str(go_mod)}],
            )
            packages.append(pkg)

        if verify_checksums and go_sum.exists():
            modules_to_check = [(pkg.name, f"v{pkg.version}" if not pkg.version.startswith("v") else pkg.version) for pkg in packages]
            checksum_results = verify_go_checksums(go_sum, modules_to_check)
            pkg_by_key: dict[str, Package] = {}
            for pkg in packages:
                ver_key = f"v{pkg.version}" if not pkg.version.startswith("v") else pkg.version
                pkg_by_key[f"{pkg.name}@{ver_key}"] = pkg
            for key, status in checksum_results.items():
                if status == "mismatch" and key in pkg_by_key:
                    p = pkg_by_key[key]
                    p.is_malicious = True
                    p.malicious_reason = "go.sum hash mismatch: tampered module — hash on disk differs from sum.golang.org record"
                    logger.warning(
                        "go.sum hash mismatch for %s — possible supply chain tampering",
                        key,
                    )

        return packages

    # Fallback: go.sum is a checksum inventory; directness is unknown
    packages = []
    if go_sum.exists():
        seen: set[tuple[str, str]] = set()
        malformed_lines = False
        try:
            lines = go_sum.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            logger.debug("Could not read go.sum at %s: %s", go_sum, exc)
            record_manifest_parse_warning(
                ecosystem="go",
                path=str(go_sum),
                detail="go.sum could not be read; Go dependencies were not scanned",
            )
            return []
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            if len(parts) != 3 or not parts[2].startswith("h1:") or len(parts[2]) <= len("h1:"):
                malformed_lines = True
                continue
            name = parts[0]
            raw_ver = parts[1].split("/")[0]  # strip /go.mod suffix
            clean_ver = raw_ver[1:] if raw_ver.startswith("v") else raw_ver
            mod_key = (name, clean_ver)
            if mod_key not in seen:
                seen.add(mod_key)
                packages.append(
                    Package(
                        name=name,
                        version=clean_ver,
                        ecosystem="go",
                        purl=f"pkg:golang/{name}@{raw_ver}",
                        is_direct=None,
                        version_source="lockfile",
                        version_evidence=[{"type": "lockfile", "source_file": str(go_sum)}],
                    )
                )
        if malformed_lines:
            record_manifest_parse_warning(
                ecosystem="go",
                path=str(go_sum),
                detail="go.sum contains malformed or truncated entries; Go dependency coverage is partial",
            )
    return packages


def parse_conda_packages(directory: Path) -> list[Package]:
    """Parse packages from conda environment files and lock files.

    Supports three file formats:

    * ``environment.yml`` / ``environment.yaml`` — conda environment
      specification.  Conda packages (``name=version``) are tagged
      ``ecosystem="conda"``; pip sub-dependencies (under the ``pip:`` key)
      are tagged ``ecosystem="pypi"``.  Channel prefixes such as
      ``pytorch::pytorch=2.1.0`` are stripped.
    * ``conda-lock.yml`` — platform-resolved lock file generated by
      ``conda-lock``.  Packages are deduplicated across platforms; the
      ``manager`` field determines ecosystem (``conda`` or ``pip``).

    Version specifiers:

    * ``=1.24.0`` → exact version ``1.24.0``
    * ``>=1.24.0`` → stored as-is (``>=1.24.0``)
    * No version → version stored as empty string ``""``

    Args:
        directory: Project directory to search for conda manifests.

    Returns:
        List of :class:`~agent_bom.models.Package` objects.  Empty list when
        no conda files are found.
    """
    packages: list[Package] = []

    # ── Helper: parse environment.yml / environment.yaml ─────────────────────
    def _parse_env_file(path: Path) -> list[Package]:
        pkgs: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Could not read Conda environment at %s: %s", path, exc)
            record_manifest_parse_warning(
                ecosystem="conda",
                path=str(path),
                detail=f"{path.name} could not be read; Conda dependencies were not scanned",
            )
            return pkgs

        # Try YAML first; fall back to line-by-line
        data: dict | None = None
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(content) or {}
        except ImportError:
            data = None
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not parse Conda environment at %s: %s", path, exc)
            record_manifest_parse_warning(
                ecosystem="conda",
                path=str(path),
                detail=f"{path.name} could not be parsed; Conda dependency coverage may be incomplete",
            )
            data = None

        if data is not None:
            for dep in data.get("dependencies", []):
                if isinstance(dep, str):
                    # Strip channel prefix: "channel::name=version" → "name=version"
                    if "::" in dep:
                        dep = dep.split("::", 1)[1]
                    # Parse "name=version" or "name=version=build"
                    parts = dep.split("=", 1)
                    pkg_name = parts[0].strip()
                    pkg_version = parts[1].strip() if len(parts) >= 2 else ""
                    if pkg_name:
                        pkgs.append(
                            Package(
                                name=pkg_name,
                                version=pkg_version,
                                ecosystem="conda",
                                purl=f"pkg:conda/{pkg_name}@{pkg_version}" if pkg_version else None,
                                is_direct=True,
                            )
                        )
                elif isinstance(dep, dict) and "pip" in dep:
                    for pip_dep in dep.get("pip", []):
                        if not isinstance(pip_dep, str):
                            continue
                        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]{1,2})\s*([a-zA-Z0-9_.*+!-]+)", pip_dep)
                        if m:
                            pip_name = m.group(1)
                            pip_op = m.group(2)
                            pip_ver = m.group(3)
                            # Normalise double-equals to bare version for ==, keep others as specifier
                            version_str = pip_ver if pip_op == "==" else f"{pip_op}{pip_ver}"
                            pkgs.append(
                                Package(
                                    name=pip_name,
                                    version=version_str,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{pip_name}@{version_str}",
                                    is_direct=True,
                                )
                            )
        else:
            # Fallback: line-by-line (no yaml library)
            in_deps = False
            in_pip = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("dependencies:"):
                    in_deps = True
                    in_pip = False
                    continue
                if in_deps:
                    if stripped.startswith("- pip:"):
                        in_pip = True
                        continue
                    if stripped.startswith("-") and not stripped.startswith("- pip"):
                        in_pip = False
                        dep_raw = stripped.lstrip("- ").strip()
                        if "::" in dep_raw:
                            dep_raw = dep_raw.split("::", 1)[1]
                        parts = dep_raw.split("=", 1)
                        pkg_name = parts[0].strip()
                        pkg_version = parts[1].strip() if len(parts) >= 2 else ""
                        if pkg_name:
                            pkgs.append(
                                Package(
                                    name=pkg_name,
                                    version=pkg_version,
                                    ecosystem="conda",
                                    purl=f"pkg:conda/{pkg_name}@{pkg_version}" if pkg_version else None,
                                    is_direct=True,
                                )
                            )
                    elif in_pip and stripped.startswith("-"):
                        pip_dep = stripped.lstrip("- ").strip()
                        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]{1,2})\s*([a-zA-Z0-9_.*+!-]+)", pip_dep)
                        if m:
                            pip_name = m.group(1)
                            pip_op = m.group(2)
                            pip_ver = m.group(3)
                            version_str = pip_ver if pip_op == "==" else f"{pip_op}{pip_ver}"
                            pkgs.append(
                                Package(
                                    name=pip_name,
                                    version=version_str,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{pip_name}@{version_str}",
                                    is_direct=True,
                                )
                            )
        return pkgs

    # ── Helper: parse conda-lock.yml ─────────────────────────────────────────
    def _parse_lock_file(path: Path) -> list[Package]:
        pkgs: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Could not read Conda lockfile at %s: %s", path, exc)
            record_manifest_parse_warning(
                ecosystem="conda",
                path=str(path),
                detail="conda-lock.yml could not be read; Conda dependencies were not scanned",
            )
            return pkgs

        data: dict | None = None
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(content) or {}
        except ImportError:
            data = None
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not parse Conda lockfile at %s: %s", path, exc)
            record_manifest_parse_warning(
                ecosystem="conda",
                path=str(path),
                detail="conda-lock.yml could not be parsed; Conda dependencies were not scanned",
            )
            data = None

        if data is None:
            return pkgs

        seen: set[tuple[str, str, str]] = set()
        for entry in data.get("package", []):
            name = (entry.get("name") or "").strip()
            version = str(entry.get("version") or "").strip()
            manager = (entry.get("manager") or "conda").strip().lower()
            if not name or not version:
                continue
            if (key := (name, version, manager)) in seen:
                continue
            seen.add(key)
            ecosystem = "pypi" if manager == "pip" else "conda"
            pkgs.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    purl=package_purl(name, version, ecosystem),
                    is_direct=True,
                )
            )
        return pkgs

    # ── Dispatch ──────────────────────────────────────────────────────────────
    conda_lock = directory / "conda-lock.yml"
    if conda_lock.exists():
        packages.extend(_parse_lock_file(conda_lock))

    for env_name in ("environment.yml", "environment.yaml"):
        env_path = directory / env_name
        if env_path.exists():
            packages.extend(_parse_env_file(env_path))
            break

    # Deduplicate by (name, version, ecosystem)
    seen_keys: set[tuple[str, str, str]] = set()
    unique: list[Package] = []
    for p in packages:
        key = (p.name, p.version, p.ecosystem)
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(p)
    return unique


if TYPE_CHECKING:
    from agent_bom.parsers.cargo_packages import _CARGO_UNRESOLVED_VERSIONS as _CARGO_UNRESOLVED_VERSIONS
    from agent_bom.parsers.cargo_packages import _CRATES_IO_URL as _CRATES_IO_URL
    from agent_bom.parsers.cargo_packages import _cargo_dep_version as _cargo_dep_version
    from agent_bom.parsers.cargo_packages import _cargo_dependency_tables as _cargo_dependency_tables
    from agent_bom.parsers.cargo_packages import _parse_cargo_toml as _parse_cargo_toml
    from agent_bom.parsers.cargo_packages import parse_cargo_packages as parse_cargo_packages
    from agent_bom.parsers.cargo_packages import resolve_cargo_version as resolve_cargo_version
    from agent_bom.parsers.go_resolution import _CHECKSUM_DB_URL as _CHECKSUM_DB_URL
    from agent_bom.parsers.go_resolution import _GOPROXY_URL as _GOPROXY_URL
    from agent_bom.parsers.go_resolution import _validate_https_url as _validate_https_url
    from agent_bom.parsers.maven_packages import _MAVEN_CENTRAL_URL as _MAVEN_CENTRAL_URL
    from agent_bom.parsers.maven_packages import _MAVEN_UNRESOLVED_VERSIONS as _MAVEN_UNRESOLVED_VERSIONS
    from agent_bom.parsers.maven_packages import _parse_pom_modules as _parse_pom_modules
    from agent_bom.parsers.maven_packages import parse_maven_packages as parse_maven_packages
    from agent_bom.parsers.maven_packages import resolve_maven_version as resolve_maven_version
    from agent_bom.parsers.uvx_packages import _normalize_python_dist_name as _normalize_python_dist_name
    from agent_bom.parsers.uvx_packages import _resolve_uv_cached_version as _resolve_uv_cached_version
    from agent_bom.parsers.uvx_packages import _uvx_package_from_command as _uvx_package_from_command
    from agent_bom.parsers.uvx_packages import detect_uvx_package as detect_uvx_package

_EXPORTS = {
    "_validate_https_url": "agent_bom.parsers.go_resolution",
    "resolve_maven_version": "agent_bom.parsers.maven_packages",
    "_parse_pom_modules": "agent_bom.parsers.maven_packages",
    "parse_maven_packages": "agent_bom.parsers.maven_packages",
    "resolve_cargo_version": "agent_bom.parsers.cargo_packages",
    "_cargo_dep_version": "agent_bom.parsers.cargo_packages",
    "_cargo_dependency_tables": "agent_bom.parsers.cargo_packages",
    "_parse_cargo_toml": "agent_bom.parsers.cargo_packages",
    "parse_cargo_packages": "agent_bom.parsers.cargo_packages",
    "_normalize_python_dist_name": "agent_bom.parsers.uvx_packages",
    "_resolve_uv_cached_version": "agent_bom.parsers.uvx_packages",
    "_uvx_package_from_command": "agent_bom.parsers.uvx_packages",
    "detect_uvx_package": "agent_bom.parsers.uvx_packages",
    "_CHECKSUM_DB_URL": "agent_bom.parsers.go_resolution",
    "_GOPROXY_URL": "agent_bom.parsers.go_resolution",
    "_MAVEN_CENTRAL_URL": "agent_bom.parsers.maven_packages",
    "_MAVEN_UNRESOLVED_VERSIONS": "agent_bom.parsers.maven_packages",
    "_CARGO_UNRESOLVED_VERSIONS": "agent_bom.parsers.cargo_packages",
    "_CRATES_IO_URL": "agent_bom.parsers.cargo_packages",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
