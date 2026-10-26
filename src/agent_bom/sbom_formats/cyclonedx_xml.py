"""Project CycloneDX XML (1.2-1.7) onto the CycloneDX JSON document shape.

The JSON parser stays the single source of package semantics: this module only
re-shapes XML elements into the keys the JSON reader consumes, so an XML BOM
and its JSON twin produce identical packages. Parsing goes through defusedxml
with DTDs forbidden, which rules out entity expansion and external entity or
DTD retrieval; nesting depth is bounded so hostile documents fail closed.
"""

from __future__ import annotations

from typing import Any
from xml.etree.ElementTree import Element  # nosec B405 - type only; parsing uses defusedxml

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError
from defusedxml.ElementTree import fromstring as safe_fromstring

_NAMESPACE_PREFIX = "http://cyclonedx.org/schema/bom/"
MAX_XML_DEPTH = 64

_LEAF_KEYS = (
    "author",
    "publisher",
    "group",
    "name",
    "version",
    "description",
    "scope",
    "copyright",
    "cpe",
    "purl",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: Element, name: str | None = None) -> list[Element]:
    return [child for child in element if name is None or _local(child.tag) == name]


def _child(element: Element, name: str) -> Element | None:
    found = _children(element, name)
    return found[0] if found else None


def _text(element: Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text.strip()


def _put_text(target: dict[str, Any], element: Element, *names: str) -> None:
    for name in names:
        value = _text(_child(element, name))
        if value is not None:
            target[name] = value


def _properties(element: Element) -> list[dict[str, str]]:
    container = _child(element, "properties")
    rows: list[dict[str, str]] = []
    for prop in _children(container, "property") if container is not None else []:
        row = {"name": prop.get("name", "")}
        value = _text(prop)
        if value is not None:
            row["value"] = value
        rows.append(row)
    return rows


def _entity(element: Element | None) -> dict[str, Any] | None:
    if element is None:
        return None
    entity: dict[str, Any] = {}
    _put_text(entity, element, "name")
    urls = [value for url in _children(element, "url") if (value := _text(url))]
    if urls:
        entity["url"] = urls
    return entity


def _licenses(element: Element) -> list[dict[str, Any]]:
    container = _child(element, "licenses")
    rows: list[dict[str, Any]] = []
    for entry in list(container) if container is not None else []:
        kind = _local(entry.tag)
        if kind == "expression":
            rows.append({"expression": _text(entry) or ""})
        elif kind == "license":
            license_obj: dict[str, Any] = {}
            _put_text(license_obj, entry, "id", "name", "url")
            rows.append({"license": license_obj})
    return rows


def _hashes(element: Element) -> list[dict[str, str]]:
    container = _child(element, "hashes")
    items = _children(container, "hash") if container is not None else []
    return [{"alg": item.get("alg", ""), "content": _text(item) or ""} for item in items]


def _external_references(element: Element) -> list[dict[str, Any]]:
    container = _child(element, "externalReferences")
    rows: list[dict[str, Any]] = []
    for ref in _children(container, "reference") if container is not None else []:
        row: dict[str, Any] = {"type": ref.get("type", "")}
        _put_text(row, ref, "url", "comment")
        rows.append(row)
    return rows


def _component(element: Element, depth: int) -> dict[str, Any]:
    if depth > MAX_XML_DEPTH:
        raise ValueError("CycloneDX XML nesting exceeds the supported depth")
    component: dict[str, Any] = {}
    for attr in ("type", "bom-ref", "mime-type"):
        if element.get(attr) is not None:
            component[attr] = element.get(attr)
    _put_text(component, element, *_LEAF_KEYS)
    for key in ("supplier", "manufacturer"):
        entity = _entity(_child(element, key))
        if entity is not None:
            component[key] = entity
    for key, rows in (
        ("hashes", _hashes(element)),
        ("licenses", _licenses(element)),
        ("externalReferences", _external_references(element)),
        ("properties", _properties(element)),
    ):
        if rows:
            component[key] = rows
    nested = _child(element, "components")
    if nested is not None:
        component["components"] = [_component(child, depth + 1) for child in _children(nested, "component")]
    return component


def _dependencies(root: Element) -> list[dict[str, Any]]:
    container = _child(root, "dependencies")
    rows: list[dict[str, Any]] = []
    for dep in _children(container, "dependency") if container is not None else []:
        row: dict[str, Any] = {"ref": dep.get("ref", "")}
        depends_on = [child.get("ref", "") for child in _children(dep, "dependency")]
        if depends_on:
            row["dependsOn"] = depends_on
        provides = [child.get("ref", "") for child in _children(dep, "provides")]
        if provides:
            row["provides"] = provides
        rows.append(row)
    return rows


def _compositions(root: Element) -> list[dict[str, Any]]:
    container = _child(root, "compositions")
    rows: list[dict[str, Any]] = []
    for composition in _children(container, "composition") if container is not None else []:
        row: dict[str, Any] = {}
        _put_text(row, composition, "aggregate")
        for key, item in (("assemblies", "assembly"), ("dependencies", "dependency")):
            refs_container = _child(composition, key)
            if refs_container is not None:
                row[key] = [ref.get("ref", "") for ref in _children(refs_container, item)]
        rows.append(row)
    return rows


def _number(value: str | None) -> float | int | None:
    if value is None:
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return int(number) if number.is_integer() and "." not in value else number


def _ratings(element: Element) -> list[dict[str, Any]]:
    container = _child(element, "ratings")
    rows: list[dict[str, Any]] = []
    for rating in _children(container, "rating") if container is not None else []:
        row: dict[str, Any] = {}
        source = _child(rating, "source")
        if source is not None:
            row["source"] = {}
            _put_text(row["source"], source, "name", "url")
        score = _number(_text(_child(rating, "score")))
        if score is not None:
            row["score"] = score
        _put_text(row, rating, "severity", "method", "vector", "justification")
        rows.append(row)
    return rows


def _vulnerability(element: Element) -> dict[str, Any]:
    vuln: dict[str, Any] = {}
    if element.get("bom-ref") is not None:
        vuln["bom-ref"] = element.get("bom-ref")
    _put_text(vuln, element, "id", "description", "detail", "recommendation", "workaround", "created", "published", "updated")
    source = _child(element, "source")
    if source is not None:
        vuln["source"] = {}
        _put_text(vuln["source"], source, "name", "url")
    ratings = _ratings(element)
    if ratings:
        vuln["ratings"] = ratings
    cwes = _child(element, "cwes")
    if cwes is not None:
        vuln["cwes"] = [n for cwe in _children(cwes, "cwe") if isinstance(n := _number(_text(cwe)), int)]
    affects = _child(element, "affects")
    if affects is not None:
        vuln["affects"] = [{"ref": _text(_child(target, "ref")) or ""} for target in _children(affects, "target")]
    analysis = _child(element, "analysis")
    if analysis is not None:
        vuln["analysis"] = {}
        _put_text(vuln["analysis"], analysis, "state", "justification", "detail")
    properties = _properties(element)
    if properties:
        vuln["properties"] = properties
    return vuln


def _tools(metadata: Element) -> list[dict[str, Any]] | dict[str, Any] | None:
    tools = _child(metadata, "tools")
    if tools is None:
        return None
    legacy = _children(tools, "tool")
    if legacy:
        rows = []
        for tool in legacy:
            row: dict[str, Any] = {}
            _put_text(row, tool, "vendor", "name", "version")
            rows.append(row)
        return rows
    components = _child(tools, "components")
    return {"components": [_component(child, 1) for child in (_children(components, "component") if components is not None else [])]}


def _metadata(root: Element) -> dict[str, Any] | None:
    metadata = _child(root, "metadata")
    if metadata is None:
        return None
    result: dict[str, Any] = {}
    _put_text(result, metadata, "timestamp")
    tools = _tools(metadata)
    if tools is not None:
        result["tools"] = tools
    component = _child(metadata, "component")
    if component is not None:
        result["component"] = _component(component, 0)
    properties = _properties(metadata)
    if properties:
        result["properties"] = properties
    return result


def cyclonedx_xml_to_document(raw: bytes) -> dict[str, Any]:
    """Return the CycloneDX JSON-shaped projection of an XML BOM."""
    try:
        root = safe_fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ParseError) as exc:
        raise ValueError(f"CycloneDX XML rejected: {type(exc).__name__}") from exc
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    if _local(root.tag) != "bom" or not namespace.startswith(_NAMESPACE_PREFIX):
        raise ValueError("XML document is not a CycloneDX BOM (expected a <bom> element in the CycloneDX namespace).")
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": namespace[len(_NAMESPACE_PREFIX) :],
        "version": int(_number(root.get("version")) or 1),
    }
    if root.get("serialNumber"):
        document["serialNumber"] = root.get("serialNumber")
    metadata = _metadata(root)
    if metadata is not None:
        document["metadata"] = metadata
    components = _child(root, "components")
    document["components"] = [_component(child, 0) for child in _children(components, "component")] if components is not None else []
    for key, rows in (("dependencies", _dependencies(root)), ("compositions", _compositions(root))):
        if rows:
            document[key] = rows
    vulnerabilities = _child(root, "vulnerabilities")
    if vulnerabilities is not None:
        document["vulnerabilities"] = [_vulnerability(child) for child in _children(vulnerabilities, "vulnerability")]
    return document
