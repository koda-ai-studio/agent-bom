"""The README hero keeps integration groups and badges visually bounded."""

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.render_social_preview_svg import render

ROOT = Path(__file__).resolve().parents[1]
SVG = "{http://www.w3.org/2000/svg}"


def test_banner_uses_three_logo_rows_without_category_boxes() -> None:
    root = ET.fromstring(render())
    tiles = [item for item in root.iter(f"{SVG}g") if item.get("data-integration")]
    assert len(tiles) >= 39
    boxes = []
    for tile in tiles:
        x, y = map(float, re.findall(r"[\d.]+", tile.attrib["transform"]))
        rect = tile.find(f"{SVG}rect")
        width, height = float(rect.attrib["width"]), float(rect.attrib["height"])
        boxes.append((x, y, x + width, y + height))
    assert len({top for _, top, _, _ in boxes}) == 3
    for index, (left, top, right, bottom) in enumerate(boxes):
        assert 0 <= left < right <= 1280 and 230 <= top < bottom <= 520
        for other_left, other_top, other_right, other_bottom in boxes[index + 1 :]:
            assert right <= other_left or other_right <= left or bottom <= other_top or other_bottom <= top
    assert not any(item.get("data-integration-group") for item in root.iter(f"{SVG}g"))
    texts = [element.text or "" for element in root.iter(f"{SVG}text")]
    assert not any("more:" in text or "…" in text for text in texts)
    names = {tile.get("data-integration") for tile in tiles}
    assert {"CoreWeave", "Nebius", "Lambda", "RunPod", "Vast.ai", "Crusoe", "ClickHouse"} <= names


def test_readme_badges_use_two_balanced_rows_and_keep_live_build_status() -> None:
    header = (ROOT / "README.md").read_text().split("<!-- mcp-name:", 1)[0]
    rows = [row for row in re.findall(r"<p[^>]*>(.*?)</p>", header, re.S) if "img.shields.io" in row]
    assert [row.count("<img ") for row in rows] == [3, 2]
    assert "actions/workflow/status/koda-ai-studio/agent-bom/ci.yml?branch=main" in rows[0]
    for logo in ("github", "pypi", "python"):
        assert f"logo={logo}" in rows[0]


def test_banner_vendor_assets_are_pinned_and_self_contained() -> None:
    manifest = json.loads((ROOT / "docs/images/integrations-manifest.json").read_text())
    provenance = json.loads((ROOT / "docs/images/vendor/provenance.json").read_text())
    pinned = {asset["path"]: asset["sha256"] for asset in provenance["assets"]}
    for group in [*manifest["groups"], manifest["evidence_out"]]:
        for item in group["integrations"]:
            if "logo" not in item:
                continue
            relative = "docs/images/" + item["logo"]
            data = (ROOT / relative).read_bytes()
            assert hashlib.sha256(data).hexdigest() == pinned[relative]
            for element in ET.fromstring(data).iter():
                assert element.tag.rsplit("}", 1)[-1] not in {"script", "foreignObject", "image"}
                for key, value in element.attrib.items():
                    assert not key.lower().startswith("on")
                    if key.rsplit("}", 1)[-1] in {"href", "src"}:
                        assert value.startswith("#")


def test_embedded_vendor_gradients_have_unique_resolvable_ids() -> None:
    root = ET.fromstring(render())
    ids = [element.attrib["id"] for element in root.iter() if "id" in element.attrib]
    assert len(ids) == len(set(ids)), "Vendor SVG gradients must not affect another logo"
    for element in root.iter():
        for value in element.attrib.values():
            for reference in re.findall(r"url\(#([^)]+)\)", value):
                assert reference in ids


def test_coreweave_uses_the_current_blue_and_light_mark_on_dark() -> None:
    root = ET.fromstring(render())
    symbol = next(element for element in root.iter(f"{SVG}symbol") if element.get("id") == "embedded-coreweave-icon")
    paths = list(symbol.iter(f"{SVG}path"))
    assert paths[0].get("fill") == "#2741e7"
    assert all(path.get("fill") == "#f8fafc" for path in paths[1:])
    assert not list(symbol.iter(f"{SVG}style"))
    tile = next(element for element in root.iter(f"{SVG}g") if element.get("data-integration") == "CoreWeave")
    assert tile.find(f"{SVG}rect").get("fill") == "#0f1a2b"
