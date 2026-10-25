"""Maven packages."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.go_resolution import _validate_https_url, logger
from agent_bom.parsers.maven_properties import (
    PomModel,
    child,
    child_text,
    dependency_coordinates,
    dependency_elements,
    local_model,
    managed_versions,
    read_pom,
    substitute,
)

_MAVEN_CENTRAL_URL = "https://search.maven.org"

_MAVEN_UNRESOLVED_VERSIONS = frozenset({"RELEASE", "LATEST", "", "unknown"})


def resolve_maven_version(
    group_id: str,
    artifact_id: str,
    version: str,
    *,
    maven_central_url: str = _MAVEN_CENTRAL_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Maven artifact version using the Maven Central Search API.

    Queries ``https://search.maven.org/solrsearch/select`` for the latest
    stable release of *group_id*:*artifact_id* and returns it.

    If *version* is already pinned (not ``"RELEASE"``, ``"LATEST"``, ``""``
    or ``"unknown"``), it is returned immediately without any network call.

    Skips pre-release versions with ``-SNAPSHOT``, ``-RC``, or ``-M``
    suffixes.  Never raises — any network or parse error causes the original
    version string to be returned so that parsing can continue uninterrupted.

    Args:
        group_id: Maven group ID (e.g. ``"org.springframework"``).
        artifact_id: Maven artifact ID (e.g. ``"spring-core"``).
        version: Current version string.  Pass ``"RELEASE"`` or ``"LATEST"``
            to trigger resolution.
        maven_central_url: Base URL of the Maven Central Search API.
            Must be HTTPS.  Defaults to ``https://search.maven.org``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"6.1.4"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _MAVEN_UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(maven_central_url, "maven_central_url")

    encoded_group = urllib.parse.quote(group_id, safe="")
    encoded_artifact = urllib.parse.quote(artifact_id, safe="")
    query = f"g:{encoded_group}+AND+a:{encoded_artifact}"
    api_url = f"{maven_central_url}/solrsearch/select?q={query}&rows=10&wt=json"

    _maven_prerelease_re = re.compile(r"-(SNAPSHOT|RC\d*|M\d+)$", re.IGNORECASE)

    try:
        from agent_bom.http_client import fetch_bytes

        raw_body = fetch_bytes(api_url, timeout=timeout).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original on failure
        logger.warning(
            "Maven Central version resolution failed for %s:%s — returning original version: %s",
            group_id,
            artifact_id,
            exc,
        )
        return version

    try:
        data = json.loads(raw_body)
        docs = data.get("response", {}).get("docs", [])
        for doc in docs:
            candidate = (doc.get("v") or doc.get("latestVersion") or "").strip()
            if not candidate:
                continue
            if _maven_prerelease_re.search(candidate):
                continue
            return candidate
    except (ValueError, KeyError, AttributeError) as exc:
        logger.warning(
            "Failed to parse Maven Central response for %s:%s: %s",
            group_id,
            artifact_id,
            exc,
        )

    return version


def _pom_dependency(
    dep: ET.Element,
    properties: dict[str, str],
    pom: Path,
    managed: dict[tuple[str, str], ET.Element],
) -> Package | None:
    group_id, artifact_id = child_text(dep, "groupId"), child_text(dep, "artifactId")
    if not group_id or not artifact_id:
        return None
    version, scope = child_text(dep, "version"), child_text(dep, "scope")
    managed_dep = managed.get((substitute(group_id, properties), substitute(artifact_id, properties)))
    if managed_dep is not None:
        version = version or child_text(managed_dep, "version")
        scope = scope or child_text(managed_dep, "scope")
    coordinates = dependency_coordinates(group_id, artifact_id, version, properties, pom)
    if coordinates is None:
        return None
    group_id, artifact_id, version = coordinates
    return Package(
        name=f"{group_id}:{artifact_id}",
        version=version,
        ecosystem="maven",
        purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
        is_direct=(scope or "compile").lower() not in {"test", "provided", "system"},
    )


def _effective_dependencies(xml_root: ET.Element, model: PomModel) -> list[ET.Element]:
    own = dependency_elements(xml_root, "dependencies")
    declared = {(child_text(dep, "groupId"), child_text(dep, "artifactId")) for dep in own}
    inherited = [dep for dep in model.inherited if (child_text(dep, "groupId"), child_text(dep, "artifactId")) not in declared]
    return own + inherited


def _parse_pom_modules(root_dir: Path, depth: int = 0, *, scan_root: Path | None = None) -> list[Package]:
    """Recursively parse a Maven multi-module project.

    Reads the ``pom.xml`` at *root_dir*, collects its ``<dependency>``
    elements, then follows any ``<modules>/<module>`` child paths and recurses
    (up to 3 levels deep to guard against cycles).

    Args:
        root_dir: Directory containing a ``pom.xml``.
        depth: Current recursion depth (0 = root, max 3).

    Returns:
        Flat list of :class:`~agent_bom.models.Package` objects from this POM
        and all discovered sub-module POMs.
    """
    if depth > 3:
        return []

    scan_root = (scan_root or root_dir).resolve()
    pom = (root_dir / "pom.xml").resolve()
    if not pom.is_relative_to(scan_root):
        return []
    if not pom.exists():
        return []

    try:
        xml_root = read_pom(pom)
    except (ET.ParseError, OSError, ValueError) as exc:
        logger.debug("Failed to parse pom.xml in %s: %s", root_dir, exc)
        record_manifest_parse_warning(
            ecosystem="maven",
            path=str(pom),
            detail="pom.xml could not be read within the parser size limit or parsed; Maven dependencies were not scanned",
        )
        return []

    model = local_model(pom, xml_root, scan_root)
    managed = managed_versions(model)
    packages: list[Package] = []
    for dep in _effective_dependencies(xml_root, model):
        package = _pom_dependency(dep, model.properties, pom, managed)
        if package is not None:
            packages.append(package)

    # Recurse into sub-modules declared in <modules><module>...</module></modules>
    modules_el = child(xml_root, "modules")
    if modules_el is not None:
        ns = modules_el.tag.partition("}")[0] + "}" if modules_el.tag.startswith("{") else ""
        for module_el in modules_el.findall(f"{ns}module") or modules_el.findall("module"):
            module_path = (module_el.text or "").strip()
            if not module_path:
                continue
            sub_dir = root_dir / module_path
            packages.extend(_parse_pom_modules(sub_dir, depth=depth + 1, scan_root=scan_root))

    return packages


def parse_maven_packages(directory: Path, *, resolve_versions: bool = False, scan_root: Path | None = None) -> list[Package]:
    """Parse packages from pom.xml (Maven/Java projects).

    Supports multi-module Maven projects: if the root ``pom.xml`` contains a
    ``<modules>`` section, each sub-module's ``pom.xml`` is recursively parsed
    (up to 3 levels deep).  The result is deduplicated by
    ``(groupId, artifactId)``; explicit versions are preferred over entries
    from nested modules with the same coordinates.

    Dependencies with scope ``test``, ``provided``, or ``system`` are included
    but marked ``is_direct=False`` since they are not deployed at runtime.
    Dependencies without a ``<version>`` element (version inherited via parent
    POM) emit coverage warnings. Explicit property references resolve through
    at most eight local parents within the repository or explicit scan root.
    No parent POM is fetched remotely.

    Args:
        directory: Project directory containing ``pom.xml``.
        resolve_versions: When ``True``, packages with unresolved versions
            (``"RELEASE"``, ``"LATEST"``, ``""`` or ``"unknown"``) are queried
            against the Maven Central Search API to obtain their latest stable
            version.  Default ``False`` — no network calls.
    """
    pom = directory / "pom.xml"
    if not pom.exists():
        return []

    boundary = scan_root or next((p for p in (directory, *directory.parents) if (p / ".git").exists()), directory)
    all_packages = _parse_pom_modules(directory, depth=0, scan_root=boundary)

    # Deduplicate by (name, version) — first occurrence wins (root > submodule)
    maven_seen: set[tuple[str, str]] = set()
    unique: list[Package] = []
    for pkg in all_packages:
        maven_key = (pkg.name, pkg.version)
        if maven_key not in maven_seen:
            maven_seen.add(maven_key)
            unique.append(pkg)

    if resolve_versions:
        for pkg in unique:
            if pkg.version in _MAVEN_UNRESOLVED_VERSIONS and ":" in pkg.name:
                maven_group, maven_artifact = pkg.name.split(":", 1)
                resolved_ver = resolve_maven_version(maven_group, maven_artifact, pkg.version)
                if resolved_ver != pkg.version:
                    pkg.version = resolved_ver
                    pkg.purl = f"pkg:maven/{maven_group}/{maven_artifact}@{resolved_ver}"
                    pkg.version_source = "registry_fallback"

    return unique
