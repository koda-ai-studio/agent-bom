"""Lay out the banner's coverage grid from the integrations manifest."""

from __future__ import annotations

import xml.etree.ElementTree as ET

try:
    from scripts.integrations_manifest import Group, Manifest
except ModuleNotFoundError:  # executed as ``python scripts/render_social_preview_svg.py``
    from integrations_manifest import Group, Manifest  # type: ignore[no-redef]

SVG = "{http://www.w3.org/2000/svg}"
COLUMNS = (60, 453, 846)
ROW_TOPS = (304, 444)
CELL_WIDTH = 374
TILE = 50
TILE_PITCH = 74
MAX_TILES = 5
# The OpenAI blossom carries its own padding inside the asset.
ICON_SCALE = {"vendor/openai-blossom-white.svg": 1.47}
BANNER_TRADEMARK_NOTE = "Names and logos are trademarks of their owners; no endorsement implied."
_NARROW = set("iljtfrI.,:;'|!() ")
_WIDE = set("mwMW@&")


def text_width(text: str, size: float, *, bold: bool = False) -> float:
    """Approximate rendered width for a sans-serif face; tuned against Inter/Arial."""
    units = 0.0
    for char in text:
        if char in _NARROW:
            units += 0.3
        elif char in _WIDE:
            units += 0.86
        elif char.isupper() or char.isdigit():
            units += 0.64
        else:
            units += 0.54
    return units * size * (1.06 if bold else 1.0)


def _el(parent: ET.Element, tag: str, text: str | None = None, **attrs: object) -> ET.Element:
    element = ET.SubElement(parent, f"{SVG}{tag}", {key.replace("_", "-"): str(value) for key, value in attrs.items()})
    if text is not None:
        element.text = text
    return element


def _wrap(items: list[str], width: float, size: float, lines: int, prefix: str) -> list[str]:
    """Join ``items`` with middots into at most ``lines`` lines, ending in an ellipsis when cut."""
    out: list[str] = []
    current = prefix
    for index, item in enumerate(items):
        piece = item if current in ("", prefix) else f" · {item}"
        if text_width(current + piece, size) <= width:
            current += piece
            continue
        out.append(current)
        if len(out) == lines:
            break
        current = item
    else:
        out.append(current)
        return out
    last = out[-1]
    while text_width(last + " · …", size) > width and " · " in last:
        last = last.rsplit(" · ", 1)[0]
    out[-1] = last + " · …"
    return out


def _label(parent: ET.Element, group: Group, x: int, y: int) -> None:
    count = len(group.integrations)
    _el(parent, "text", group.title.upper(), x=x, y=y, fill="#64748b", font_size=11.5, font_weight=700, letter_spacing=1.3)
    title_width = text_width(group.title.upper(), 11.5, bold=True) + 1.3 * len(group.title)
    _el(parent, "text", str(count), x=round(x + title_width + 8), y=y, fill="#475569", font_size=11.5, font_weight=700)


def _tile(parent: ET.Element, name: str, logo: str, x: float, y: int) -> None:
    tile = _el(parent, "g", transform=f"translate({x:g} {y})", data_integration=name)
    _el(tile, "rect", width=TILE, height=TILE, rx=13, fill="#0f172a", stroke="#334155")
    size = TILE * 0.6875 * ICON_SCALE.get(logo, 1.0)
    offset = (TILE - size) / 2
    _el(tile, "image", href=logo, x=f"{offset:g}", y=f"{offset:g}", width=f"{size:g}", height=f"{size:g}")
    font = next((size for size in (12.0, 11.0) if text_width(name, size, bold=True) <= TILE_PITCH - 4), 10.0)
    _el(tile, "text", name, x=TILE / 2, y=TILE + 16, text_anchor="middle", fill="#cbd5e1", font_size=f"{font:g}", font_weight=600)


def _pills(parent: ET.Element, group: Group, x: int, y: int) -> None:
    cursor, row = 0.0, 0
    for item in group.integrations:
        width = text_width(item.name, 12.5, bold=True) + 26
        if cursor and cursor + width > CELL_WIDTH:
            cursor, row = 0.0, row + 1
        chip = _el(parent, "g", transform=f"translate({x + cursor:g} {y + row * 34})", data_integration=item.name)
        _el(chip, "rect", width=f"{width:g}", height=26, rx=13, fill="#0f172a", stroke="#334155")
        _el(chip, "text", item.name, x=f"{width / 2:g}", y=17.5, text_anchor="middle", fill="#cbd5e1", font_size=12.5, font_weight=600)
        cursor += width + 8


def _cell(parent: ET.Element, group: Group, x: int, top: int) -> None:
    _label(parent, group, x, top + 12)
    logos = group.logos[:MAX_TILES]
    if not logos:
        _pills(parent, group, x, top + 24)
        return
    for index, item in enumerate(logos):
        assert item.logo is not None
        _tile(parent, item.name, item.logo, x + index * TILE_PITCH, top + 22)
    rest = [item.name for item in group.integrations if item not in logos]
    if rest:
        for offset, line in enumerate(_wrap(rest, CELL_WIDTH, 12, 2, f"+{len(rest)} more: ")):
            _el(parent, "text", line, x=x, y=top + 106 + offset * 15, fill="#94a3b8", font_size=12)


def populate(root: ET.Element, manifest: Manifest) -> None:
    """Replace the ``coverage`` placeholder group with the grid, evidence-out row and trademark note."""
    target = next((element for element in root.iter(f"{SVG}g") if element.get("id") == "coverage"), None)
    if target is None:
        raise ValueError('social preview source must contain <g id="coverage"/>')
    target.clear()
    target.set("id", "coverage")
    for index, group in enumerate(manifest.groups):
        _cell(target, group, COLUMNS[index % 3], ROW_TOPS[index // 3])
    out = manifest.evidence_out
    _el(target, "text", out.title.upper(), x=60, y=592, fill="#64748b", font_size=11.5, font_weight=700, letter_spacing=1.3)
    _el(target, "text", " · ".join(item.name for item in out.integrations), x=176, y=592, fill="#94a3b8", font_size=13.5, font_weight=500)
    _el(target, "text", BANNER_TRADEMARK_NOTE, x=640, y=622, text_anchor="middle", fill="#64748b", font_size=11.5)
