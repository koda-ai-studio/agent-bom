"""Gradle dependency parsing: version catalogs, lockfiles and build scripts.

Build-script coordinates frequently interpolate versions (``"g:a:$v"``,
``"g:a:${v}"``). Variables are resolved from ``gradle.properties`` and the
``ext``/``extra``/``def``/``val`` assignments of the build files from the root
project (the nearest ancestor holding ``settings.gradle``) down to the module.
Anything that still cannot be resolved, and every build without a
``gradle.lockfile`` (transitives never resolved), is recorded as a manifest
coverage gap so the scan cannot report a silent ``complete``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package

logger = logging.getLogger(__name__)

_TEST_CONFIGS = frozenset({"testimplementation", "testruntimeonly", "testcompileonly"})
_KNOWN_CONFIGS = frozenset(
    {
        "implementation", "api", "runtimeonly", "compileonly", "testimplementation", "testruntimeonly", "testcompileonly",
        "annotationprocessor", "kapt", "androidtestimplementation", "debugimplementation", "releaseimplementation",
    }
)  # fmt: skip
# Calls that take a ``group:name[:version]``-shaped string but declare no
# dependency of the project: plugins, BOM/platform imports, buildscript
# classpath, constraint/substitution DSL and plain output.
_NON_DEPENDENCY_CALLS = frozenset(
    {
        "id", "plugin", "apply", "kotlin", "platform", "enforcedplatform", "mavenbom", "dependency", "classpath",
        "module", "exclude", "force", "substitute", "using", "because", "strictly", "require", "prefer", "reject",
        "url", "uri", "maven", "ivy", "file", "files", "from", "into", "include", "includebuild", "project",
        "println", "print", "logger", "version", "group", "name", "description", "property", "findproperty",
    }
)  # fmt: skip
_CALL = r"(?:[\"'](?P<qconfig>[A-Za-z_]\w*)[\"']|\b(?P<config>[A-Za-z_]\w*))\s*\(?\s*"
_DEPENDENCY_RE = re.compile(_CALL + r"(?P<q>[\"'])(?P<raw>(?:\$\{[^}\n]*\}|[^\"'\n])+)(?P=q)")
_MAP_VALUE = r"(?:[\"'](?P<{0}>[^\"'\n]+)[\"']|(?P<{0}_var>[A-Za-z_]\w*))"
_MAP_RE = re.compile(
    _CALL
    + r"group\s*[:=]\s*"
    + _MAP_VALUE.format("group")
    + r"\s*,\s*name\s*[:=]\s*"
    + _MAP_VALUE.format("name")
    + r"(?:\s*,\s*version\s*[:=]\s*"
    + _MAP_VALUE.format("version")
    + r")?"
)
_UNRESOLVED_SHAPE_RE = re.compile(r"[\w.\-]+:[\w.\-]+(?::\S*)?")
_NAME = r"[\w][\w.\-]*"
_COORD_RE = re.compile(rf"^({_NAME}):({_NAME})(?::([^:@\s]+))?(?::[^@\s]*)?(?:@\w+)?$")
_VAR_RE = re.compile(
    r"\$\{\s*(?:(?:rootProject|project)\.)?(?:(?:ext|extra)\.)?(?:property\(\s*[\"'])?(\w+)(?:[\"']\s*\))?\s*\}"
    r"|\$(\w+)"
)
_VALUE = r"[\"']([^\"'$]+)[\"']"
_ASSIGN_RE = re.compile(
    r"^\s*(?:def\s+|va[lr]\s+|(?:(?:rootProject|project)\.)?(?:ext|extra)\.)?(\w+)\s*(?::\s*\w+\s*)?=\s*"
    rf"(?:[^\n]*?\?\s*[\"'][^\"']*[\"']\s*:\s*)?{_VALUE}\s*(?://[^\n]*)?$",
    re.MULTILINE,
)
_INDEXED_RE = re.compile(rf"\b(?:ext|extra)\s*\[\s*[\"'](\w+)[\"']\s*\]\s*=\s*{_VALUE}")
_SET_RE = re.compile(rf"\b(?:ext|extra)\.set\(\s*[\"'](\w+)[\"']\s*,\s*{_VALUE}\s*\)")
_BY_EXTRA_RE = re.compile(rf"\bval\s+(\w+)\s+by\s+extra\(\s*{_VALUE}\s*\)")
_PROPERTY_LINE_RE = re.compile(r"^\s*([\w.\-]+)\s*[=:]\s*(\S[^\n]*?)\s*$")
_BUILD_FILES = ("build.gradle", "build.gradle.kts")
_SETTINGS_FILES = ("settings.gradle", "settings.gradle.kts")
_MAX_ANCESTORS = 12
_GAP_SAMPLE = 5


def _make_package(group_id: str, artifact_id: str, version: str, config: str = "") -> Package:
    return Package(
        name=f"{group_id}:{artifact_id}",
        version=version,
        ecosystem="maven",
        purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
        is_direct=config.lower() not in _TEST_CONFIGS,
    )


def _read(path: Path, label: str) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Could not read Gradle file at %s: %s", path, exc)
        record_manifest_parse_warning(
            ecosystem="maven",
            path=str(path),
            detail=f"{label} could not be read; Gradle dependencies were not scanned",
        )
        return None


def _catalog_sections(content: str) -> tuple[dict[str, str], list[str]]:
    versions: dict[str, str] = {}
    library_lines: list[str] = []
    section = ""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if section.startswith("[versions]") and "=" in stripped:
            key, _, value = stripped.partition("=")
            versions[key.strip()] = value.strip().strip('"').strip("'")
        elif section.startswith("[libraries]"):
            library_lines.append(stripped)
    return versions, library_lines


def _catalog_entry(rest: str, versions: dict[str, str]) -> tuple[str, str, str] | None:
    module_m = re.search(r'module\s*=\s*["\']([^"\']+)["\']', rest)
    group_m = re.search(r'group\s*=\s*["\']([^"\']+)["\']', rest)
    name_m = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', rest)
    if module_m:
        parts = module_m.group(1).split(":")
        if len(parts) != 2:
            return None
        group_id, artifact_id = parts[0].strip(), parts[1].strip()
    elif group_m and name_m:
        group_id, artifact_id = group_m.group(1).strip(), name_m.group(1).strip()
    else:
        return None
    ref_m = re.search(r'version\.ref\s*=\s*["\']([^"\']+)["\']', rest)
    lit_m = re.search(r'\bversion\s*=\s*["\']([^"\']+)["\']', rest)
    version = versions.get(ref_m.group(1).strip(), "") if ref_m else (lit_m.group(1).strip() if lit_m else "")
    if not (group_id and artifact_id and version):
        return None
    return group_id, artifact_id, version


def _parse_version_catalog(path: Path) -> list[Package]:
    content = _read(path, "libs.versions.toml")
    if content is None:
        return []
    versions, library_lines = _catalog_sections(content)
    packages: list[Package] = []
    for line in library_lines:
        if "=" not in line:
            continue
        entry = _catalog_entry(line.partition("=")[2].strip(), versions)
        if entry:
            packages.append(_make_package(*entry))
    return packages


def _parse_lockfile(path: Path) -> list[Package]:
    content = _read(path, "gradle.lockfile")
    if content is None:
        return []
    packages: list[Package] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        parts = line.split("=")[0].strip().split(":")
        if len(parts) >= 3 and all(parts[:3]):
            packages.append(_make_package(parts[0], parts[1], parts[2]))
    return packages


def _project_chain(directory: Path) -> list[Path]:
    """Directories from the Gradle root project down to ``directory``."""
    chain = [directory]
    current = directory
    for _ in range(_MAX_ANCESTORS):
        if any((current / name).is_file() for name in _SETTINGS_FILES):
            return list(reversed(chain))
        if current.parent == current:
            break
        current = current.parent
        chain.append(current)
    return [directory]


def _properties_file_vars(content: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    for line in content.splitlines():
        if line.lstrip().startswith(("#", "!")):
            continue
        match = _PROPERTY_LINE_RE.match(line)
        if match:
            variables[match.group(1)] = match.group(2)
    return variables


def _build_script_vars(content: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    for pattern in (_ASSIGN_RE, _INDEXED_RE, _SET_RE, _BY_EXTRA_RE):
        for match in pattern.finditer(content):
            variables[match.group(1)] = match.group(2).strip()
    return variables


def _collect_variables(directory: Path) -> dict[str, str]:
    variables: dict[str, str] = {}
    for project_dir in _project_chain(directory):
        properties = _read(project_dir / "gradle.properties", "gradle.properties")
        if properties:
            variables.update(_properties_file_vars(properties))
        for name in _BUILD_FILES:
            script = _read(project_dir / name, name)
            if script:
                variables.update(_build_script_vars(script))
    return variables


def _substitute(value: str, variables: dict[str, str]) -> str:
    for _ in range(8):
        if "$" not in value:
            return value
        replaced = _VAR_RE.sub(lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), value)
        if replaced == value:
            return value
        value = replaced
    return value


def _is_concrete(version: str) -> bool:
    return bool(version) and "$" not in version and "+" not in version and not version.startswith(("latest.", "[", "("))


def _map_part(match: re.Match[str], key: str) -> str | None:
    if match.group(key) is not None:
        return match.group(key).strip()
    variable = match.group(f"{key}_var")
    return f"${{{variable}}}" if variable else None


def _declarations(content: str) -> list[tuple[str, str]]:
    """``(configuration, coordinate)`` pairs from string and map notation, in source order."""
    found: list[tuple[int, str, str]] = []
    for match in _DEPENDENCY_RE.finditer(content):
        found.append((match.start(), match.group("qconfig") or match.group("config"), match.group("raw").strip()))
    for match in _MAP_RE.finditer(content):
        group_id, artifact_id, version = _map_part(match, "group"), _map_part(match, "name"), _map_part(match, "version")
        raw = f"{group_id}:{artifact_id}" + (f":{version}" if version else "")
        found.append((match.start(), match.group("qconfig") or match.group("config"), raw))
    return [(config, raw) for _, config, raw in sorted(found)]


def _is_unresolved_coordinate(config: str, raw: str) -> bool:
    if config.lower() in _KNOWN_CONFIGS:
        return raw.count(":") >= 1 and not raw.startswith((":", "/"))
    return _UNRESOLVED_SHAPE_RE.fullmatch(re.sub(r"\$\{[^}]*\}", "$v", raw)) is not None


def _parse_build_script(path: Path, content: str, variables: dict[str, str]) -> tuple[list[Package], list[str]]:
    packages: list[Package] = []
    unresolved: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for config, raw in _declarations(content):
        if config.lower() in _NON_DEPENDENCY_CALLS:
            continue
        coord = _COORD_RE.match(_substitute(raw, variables))
        if not coord:
            if _is_unresolved_coordinate(config, raw):
                unresolved.append(raw)
            continue
        group_id, artifact_id, version = coord.group(1), coord.group(2), coord.group(3) or ""
        if not _is_concrete(version):
            if config.lower() in _KNOWN_CONFIGS or "$" in raw:
                unresolved.append(raw)
            continue
        if (group_id, artifact_id, version) not in seen:
            seen.add((group_id, artifact_id, version))
            packages.append(_make_package(group_id, artifact_id, version, config))
    return packages, unresolved


def _record_build_gap(path: Path, unresolved: list[str], has_lockfile: bool) -> None:
    reasons: list[str] = []
    if unresolved:
        sample = ", ".join(sorted(set(unresolved))[:_GAP_SAMPLE])
        more = len(set(unresolved)) - _GAP_SAMPLE
        suffix = f" (+{more} more)" if more > 0 else ""
        reasons.append(f"{len(set(unresolved))} dependency version(s) could not be resolved statically: {sample}{suffix}")
    if not has_lockfile:
        reasons.append("no gradle.lockfile, so transitive dependencies were not resolved")
    if reasons:
        record_manifest_parse_warning(
            ecosystem="maven",
            path=str(path),
            detail=f"{path.name}: " + "; ".join(reasons) + "; Gradle dependency coverage is partial",
        )


def _dedupe_by_name(packages: list[Package]) -> list[Package]:
    seen: set[str] = set()
    unique: list[Package] = []
    for pkg in packages:
        if pkg.name not in seen:
            seen.add(pkg.name)
            unique.append(pkg)
    return unique


def parse_gradle_packages(directory: Path) -> list[Package]:
    """Parse Gradle dependencies; a ``gradle.lockfile`` supersedes build scripts.

    Sources: ``gradle/libs.versions.toml`` (supplemental), ``gradle.lockfile``
    (resolved, canonical when present), ``build.gradle.kts`` and
    ``build.gradle``. All packages use ``ecosystem="maven"``; test
    configurations are marked ``is_direct=False``.
    """
    catalog_pkgs = _parse_version_catalog(directory / "gradle" / "libs.versions.toml")
    lockfile_path = directory / "gradle.lockfile"
    lockfile_pkgs = _parse_lockfile(lockfile_path)
    has_lockfile = lockfile_path.is_file()

    script_pkgs: list[Package] = []
    scripts = [(directory / name, _read(directory / name, name)) for name in _BUILD_FILES]
    if any(content is not None for _, content in scripts):
        variables = _collect_variables(directory)
        for path, content in scripts:
            if content is None:
                continue
            found, unresolved = _parse_build_script(path, content, variables)
            script_pkgs.extend(found)
            _record_build_gap(path, unresolved, has_lockfile)

    if lockfile_pkgs:
        merged = list(lockfile_pkgs)
        seen = {(p.name, p.version) for p in lockfile_pkgs}
        for pkg in catalog_pkgs:
            if (pkg.name, pkg.version) not in seen:
                seen.add((pkg.name, pkg.version))
                merged.append(pkg)
        return merged
    return _dedupe_by_name(script_pkgs + catalog_pkgs)
