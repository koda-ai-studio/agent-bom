"""Bounded local Maven parent/property evidence; never retrieves remote POMs."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.parsers.file_limits import read_text_limited

_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def read_pom(path: Path) -> ET.Element:
    return fromstring(read_text_limited(path))


@dataclass
class PomModel:
    """Locally inherited POM state: properties, managed versions and parent dependencies."""

    properties: dict[str, str] = field(default_factory=dict)
    managed: list[ET.Element] = field(default_factory=list)
    inherited: list[ET.Element] = field(default_factory=list)


def child(element: ET.Element, tag: str) -> ET.Element | None:
    ns = element.tag.partition("}")[0] + "}" if element.tag.startswith("{") else ""
    found = element.find(f"{ns}{tag}")
    return found if found is not None else element.find(tag)


def child_text(element: ET.Element, tag: str) -> str:
    found = child(element, tag)
    return (found.text or "").strip() if found is not None else ""


def dependency_elements(root: ET.Element, *path: str) -> list[ET.Element]:
    node: ET.Element | None = root
    for tag in path:
        node = child(node, tag) if node is not None else None
    if node is None:
        return []
    ns = node.tag.partition("}")[0] + "}" if node.tag.startswith("{") else ""
    return node.findall(f"{ns}dependency") or node.findall("dependency")


def _local_parent(path: Path, root: ET.Element, scan_root: Path, seen: frozenset[Path]) -> tuple[Path, ET.Element] | None:
    parent = child(root, "parent")
    if parent is None:
        return None
    rel = child(parent, "relativePath")
    relative = "../pom.xml" if rel is None else (rel.text or "").strip()
    if not relative:
        return None
    candidate = (path.parent / relative).resolve()
    if candidate.is_dir():
        candidate /= "pom.xml"
    if not candidate.is_relative_to(scan_root) or candidate in seen | {path.resolve()}:
        return None
    try:
        parent_root = read_pom(candidate)
    except (OSError, ValueError, ET.ParseError, DefusedXmlException):
        return None  # Unresolved dependency values below produce the coverage warning.
    # A relative path is only applicable when supplied parent coordinates agree.
    if all(
        not child_text(parent, key) or child_text(parent, key) == child_text(parent_root, key)
        for key in ("groupId", "artifactId", "version")
    ):
        return candidate, parent_root
    return None


def local_model(path: Path, root: ET.Element, scan_root: Path, seen: frozenset[Path] = frozenset(), hops: int = 0) -> PomModel:
    """Merge at most eight local parents, with child values taking precedence."""
    model = PomModel()
    found = _local_parent(path, root, scan_root, seen) if hops < 8 else None
    if found is not None:
        parent_path, parent_root = found
        inherited = local_model(parent_path, parent_root, scan_root, seen | {path.resolve()}, hops + 1)
        model.properties.update(inherited.properties)
        model.managed.extend(inherited.managed)
        model.inherited.extend(inherited.inherited + dependency_elements(parent_root, "dependencies"))
    own = child(root, "properties")
    if own is not None:
        model.properties.update({item.tag.rsplit("}", 1)[-1]: (item.text or "").strip() for item in own})
    for key in ("groupId", "artifactId", "version"):
        value = child_text(root, key)
        if value:
            model.properties[f"project.{key}"] = value
            model.properties[f"pom.{key}"] = value
    model.managed.extend(dependency_elements(root, "dependencyManagement", "dependencies"))
    return model


def substitute(value: str, properties: dict[str, str]) -> str:
    for _ in range(8):
        if "${" not in value:
            break
        value = _PROPERTY.sub(lambda match: properties.get(match[1], match[0]), value)
    return value


def managed_versions(model: PomModel) -> dict[tuple[str, str], ET.Element]:
    """``(groupId, artifactId) -> managed <dependency>``; later (child) entries win; BOM imports skipped."""
    managed: dict[tuple[str, str], ET.Element] = {}
    for dep in model.managed:
        if child_text(dep, "scope") == "import":
            continue
        key = (substitute(child_text(dep, "groupId"), model.properties), substitute(child_text(dep, "artifactId"), model.properties))
        managed[key] = dep
    return managed


def resolve_property(value: str, properties: dict[str, str], path: Path) -> str | None:
    """Resolve nested substitutions with an explicit cycle/expansion bound."""
    seen: set[str] = set()
    for _ in range(32):
        if "${" not in value:
            return value
        if value in seen:
            break
        seen.add(value)
        value = _PROPERTY.sub(lambda match: properties.get(match[1], match[0]), value)
        if len(value) > 16_384:
            break
    record_manifest_parse_warning(
        ecosystem="maven",
        path=str(path),
        detail="pom.xml contains unresolved dependency properties; Maven dependency coverage is partial",
    )
    return None


def dependency_coordinates(group: str, artifact: str, version: str, properties: dict[str, str], path: Path) -> tuple[str, str, str] | None:
    if not version:
        record_manifest_parse_warning(
            ecosystem="maven", path=str(path), detail="pom.xml dependency version is unresolved; Maven dependency coverage is partial"
        )
        return None
    values = [resolve_property(value, properties, path) for value in (group, artifact, version)]
    if any(not value for value in values):
        return None
    return str(values[0]), str(values[1]), str(values[2])
