#!/usr/bin/env python3
"""Render the README hero as a single GitHub-portable SVG."""

from __future__ import annotations

import copy
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from scripts import integrations_manifest
    from scripts.social_preview_coverage import populate as populate_coverage
except ModuleNotFoundError:  # executed as ``python scripts/render_social_preview_svg.py``
    import integrations_manifest  # type: ignore[no-redef]
    from social_preview_coverage import populate as populate_coverage  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "images" / "social-preview.source.svg"
OUTPUT = ROOT / "docs" / "images" / "social-preview.svg"
SVG_NS = "http://www.w3.org/2000/svg"
SVG = f"{{{SVG_NS}}}"
ICON_COLORS = {
    "amazonwebservices": "#ff9900",
    "claude": "#d97757",
    "clickhouse": "#ffcc00",
    "cursor": "#f8fafc",
    "databricks": "#ff3621",
    "github": "#f8fafc",
    "githubcopilot": "#f8fafc",
    "googlecloud": "#4285f4",
    "huggingface": "#ffd21e",
    "kubernetes": "#326ce5",
    "microsoftazure": "#0078d4",
    "mlflow": "#0194e2",
    "okta": "#007dc1",
    "ollama": "#f8fafc",
    "snowflake": "#29b5e8",
    "supabase": "#3ecf8e",
    "vercel": "#f8fafc",
    "weightsandbiases": "#ffbe00",
    "windsurf": "#f8fafc",
}

ET.register_namespace("", SVG_NS)


def _asset_path(source: Path, href: str) -> Path:
    if ":" in href or href.startswith(("/", "\\")):
        raise ValueError(f"social preview asset must be relative: {href}")
    asset = (source.parent / href).resolve()
    try:
        asset.relative_to(source.parent.resolve())
    except ValueError as exc:
        raise ValueError(f"social preview asset escapes its directory: {href}") from exc
    if not asset.is_file():
        raise FileNotFoundError(asset)
    return asset


def _describe(root: ET.Element, manifest: integrations_manifest.Manifest) -> None:
    desc = root.find(f"{SVG}desc")
    if desc is None:
        raise ValueError("social preview must contain a desc element")
    names = ", ".join(item.name for item in manifest.integrations())
    desc.text = f"AI supply-chain BOM: every agent, MCP server and AI package, and what each one can reach. Integrations: {names}."


def _scope_symbol_ids(symbol: ET.Element) -> None:
    """Keep vendor gradient, mask and clip IDs local to their embedded mark."""
    definitions: dict[str, str] = {}
    for parent in symbol.iter(f"{SVG}defs"):
        for child in list(parent):
            if not (identifier := child.get("id")):
                continue
            canonical = ET.canonicalize(ET.tostring(child, encoding="unicode"), strip_text=True)
            if identifier in definitions:
                if definitions[identifier] != canonical:
                    raise ValueError(f"conflicting vendor SVG definitions: {identifier}")
                parent.remove(child)
            else:
                definitions[identifier] = canonical
    prefix = symbol.attrib["id"]
    ids = {
        element.attrib["id"]: f"{prefix}-{element.attrib['id']}"
        for element in symbol.iter()
        if element is not symbol and "id" in element.attrib
    }
    for element in symbol.iter():
        if element is not symbol and "id" in element.attrib:
            element.set("id", ids[element.attrib["id"]])
        for attribute, value in list(element.attrib.items()):
            if attribute == "id":
                continue
            if value.startswith("#") and value[1:] in ids:
                value = f"#{ids[value[1:]]}"
            for old, new in ids.items():
                for quote in ("", "'", '"'):
                    value = value.replace(f"url({quote}#{old}{quote})", f"url({quote}#{new}{quote})")
            element.set(attribute, value)


def _coreweave_dark_variant(symbol: ET.Element) -> None:
    """Use the blue C and light W from CoreWeave's current site header."""
    for parent in symbol.iter():
        for child in list(parent):
            if child.tag == f"{SVG}style":
                parent.remove(child)
    for index, path in enumerate(symbol.iter(f"{SVG}path")):
        path.set("fill", "#2741e7" if index == 0 else "#f8fafc")
        if path.get("class") == "cls-2":
            path.set("fill-rule", "evenodd")


def render(source: Path = SOURCE, manifest_path: Path = integrations_manifest.MANIFEST) -> str:
    """Build the coverage grid from the manifest, inline referenced vectors as symbols, return deterministic SVG text."""
    tree = ET.parse(source)
    root = tree.getroot()
    manifest = integrations_manifest.load(manifest_path)
    populate_coverage(root, manifest)
    _describe(root, manifest)
    defs = root.find(f"{SVG}defs")
    if defs is None:
        raise ValueError("social preview must contain a defs element")

    symbols: dict[Path, str] = {}
    images = list(root.iter(f"{SVG}image"))
    parents = {child: parent for parent in root.iter() for child in parent}
    for image in images:
        href = image.attrib.get("href", "")
        asset = _asset_path(source, href)
        symbol_id = symbols.get(asset)
        if symbol_id is None:
            symbol_id = f"embedded-{asset.stem}"
            symbols[asset] = symbol_id
            asset_root = ET.parse(asset).getroot()
            symbol = ET.Element(
                f"{SVG}symbol",
                {"id": symbol_id, "viewBox": asset_root.attrib.get("viewBox", "0 0 24 24")},
            )
            for name in ("fill", "stroke", "color"):
                if name in asset_root.attrib:
                    symbol.set(name, asset_root.attrib[name])
            for child in asset_root:
                symbol.append(copy.deepcopy(child))
            if color := ICON_COLORS.get(asset.stem):
                symbol.set("fill", color)
                for element in symbol.iter():
                    if "fill" in element.attrib:
                        element.set("fill", color)
            _scope_symbol_ids(symbol)
            if asset.stem == "coreweave-icon":
                _coreweave_dark_variant(symbol)
            defs.append(symbol)

        use = ET.Element(
            f"{SVG}use",
            {key: value for key, value in image.attrib.items() if key not in {"href", "filter"}},
        )
        use.set("href", f"#{symbol_id}")
        use.tail = image.tail
        parent = parents[image]
        parent.insert(list(parent).index(image), use)
        parent.remove(image)

    if not images:
        raise ValueError("social preview source must reference at least one vector asset")
    for element in list(defs):
        if element.tag == f"{SVG}filter" and element.attrib.get("id", "").startswith("tint-"):
            defs.remove(element)
    ET.indent(tree, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def main(argv: list[str]) -> int:
    manifest = integrations_manifest.load()
    if "--check" in argv:
        stale = [] if OUTPUT.read_text(encoding="utf-8") == render() else [str(OUTPUT.relative_to(ROOT))]
        stale += integrations_manifest.stale_doc_surfaces(manifest)
        for path in stale:
            print(f"stale: {path} (run python scripts/render_social_preview_svg.py)")
        return 1 if stale else 0
    paths = [arg for arg in argv if not arg.startswith("--")]
    output = Path(paths[0]) if paths else OUTPUT
    output.write_text(render(), encoding="utf-8")
    integrations_manifest.write_doc_surfaces(manifest)
    print(f"Rendered portable social preview: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
