"""Lay out a compact logo wall from the supported-integration manifest."""

from __future__ import annotations

import xml.etree.ElementTree as ET

try:
    from scripts.integrations_manifest import Manifest
except ModuleNotFoundError:  # executed as ``python scripts/render_social_preview_svg.py``
    from integrations_manifest import Manifest  # type: ignore[no-redef]

SVG = "{http://www.w3.org/2000/svg}"
TILE = 50
COLUMNS = 13
PITCH = 92
ROW_PITCH = 108
ICON_SCALE = {"vendor/openai-blossom-white.svg": 1.47, "vendor/coreweave-icon.svg": 1.2}
BANNER_TRADEMARK_NOTE = "Names and logos are trademarks of their owners; no endorsement implied."


def _el(parent: ET.Element, tag: str, text: str | None = None, **attrs: object) -> ET.Element:
    element = ET.SubElement(parent, f"{SVG}{tag}", {key.replace("_", "-"): str(value) for key, value in attrs.items()})
    if text is not None:
        element.text = text
    return element


def _tile(parent: ET.Element, name: str, logo: str, x: float, y: int) -> None:
    tile = _el(parent, "g", transform=f"translate({x:g} {y})", data_integration=name, fill="#f8fafc", color="#f8fafc")
    background = "#e2e8f0" if name == "LangSmith" else "#0f1a2b"
    _el(tile, "rect", width=TILE, height=TILE, rx=13, fill=background)
    size = TILE * 0.72 * ICON_SCALE.get(logo, 1.0)
    if name in {"Nebius", "Lambda"}:
        size = 78
    offset = (TILE - size) / 2
    _el(tile, "image", href=logo, x=f"{offset:g}", y=f"{offset:g}", width=f"{size:g}", height=f"{size:g}")
    label = _el(tile, "text", x=TILE / 2, y=TILE + 19, text_anchor="middle", fill="#cbd5e1", font_size=11, font_weight=500)
    if name == "Docker MCP Toolkit":
        _el(label, "tspan", "Docker MCP", x=TILE / 2)
        _el(label, "tspan", "Toolkit", x=TILE / 2, dy=13)
    else:
        label.text = name


def populate(root: ET.Element, manifest: Manifest) -> None:
    """Render every available source logo with consistent spacing and no category boxes."""
    target = next((element for element in root.iter(f"{SVG}g") if element.get("id") == "coverage"), None)
    if target is None:
        raise ValueError('social preview source must contain <g id="coverage"/>')
    target.clear()
    target.set("id", "coverage")
    logos = [item for group in (*manifest.groups, manifest.evidence_out) for item in group.logos]
    if len(logos) > COLUMNS * 3:
        raise ValueError("social preview exceeds three readable logo rows; revise the layout before adding logos")
    for index, item in enumerate(logos):
        row, column = divmod(index, COLUMNS)
        row_count = min(COLUMNS, len(logos) - row * COLUMNS)
        start = (1280 - ((row_count - 1) * PITCH + TILE)) / 2
        assert item.logo is not None
        _tile(target, item.name, item.logo, start + column * PITCH, 234 + row * ROW_PITCH)
    _el(
        target,
        "text",
        "Open the integration directory for all vendors and coverage",
        x=640,
        y=564,
        text_anchor="middle",
        fill="#94a3b8",
        font_size=13,
    )
    _el(target, "text", BANNER_TRADEMARK_NOTE, x=640, y=622, text_anchor="middle", fill="#94a3b8", font_size=10)
