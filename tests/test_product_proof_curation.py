"""The committed product-proof set is exactly what the published docs embed."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import product_proof_curation as curation

ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def docs_tree(tmp_path: Path) -> Path:
    images = tmp_path / "docs" / "images"
    images.mkdir(parents=True)
    for name in ("hero-live.png", "tour-live.png", "site-live.png", "demo-latest.gif"):
        (images / name).write_bytes(b"x")
    _write(
        tmp_path / "README.md",
        '<img src="docs/images/hero-live.png" alt="hero">\n<img src="docs/images/demo-latest.gif">\n'
        "Prose naming `prose-only-live.png` is not an embed.\n",
    )
    _write(tmp_path / "docs" / "TOUR.md", "[Tour](images/tour-live.png)\n")
    _write(
        tmp_path / "site-docs" / "index.md",
        "![Site](https://raw.githubusercontent.com/o/r/main/docs/images/site-live.png)\n",
    )
    return tmp_path


def test_references_cover_html_relative_markdown_and_absolute_url_embeds(docs_tree: Path) -> None:
    refs = curation.image_references(docs_tree)
    assert set(refs) == {"hero-live.png", "demo-latest.gif", "tour-live.png", "site-live.png"}
    assert refs["tour-live.png"] == {"docs/TOUR.md"}
    assert refs["site-live.png"] == {"site-docs/index.md"}


def test_srcset_and_link_targets_count_as_references(tmp_path: Path) -> None:
    _write(
        tmp_path / "README.md",
        '<a href="docs/images/a-live.png"><picture><source srcset="docs/images/b-live.png 1x, docs/images/c-live.png 2x">'
        '</picture></a> [d](docs/images/d-live.png "title") [e](docs/images/e-live.png#frag)\n',
    )
    assert set(curation.image_references(tmp_path)) == {"a-live.png", "b-live.png", "c-live.png", "d-live.png", "e-live.png"}


def test_curated_capture_set_excludes_assets_made_by_other_generators(docs_tree: Path) -> None:
    assert curation.curated_capture_names(docs_tree) == ["hero-live.png", "site-live.png", "tour-live.png"]


def test_a_reference_to_a_missing_image_is_reported(docs_tree: Path) -> None:
    _write(docs_tree / "docs" / "GHOST.md", '<img src="images/ghost-live.png">\n')
    assert curation.dangling_references(docs_tree) == ["docs/GHOST.md -> docs/images/ghost-live.png"]


def test_an_unreferenced_capture_is_reported_as_an_orphan(docs_tree: Path) -> None:
    (docs_tree / "docs" / "images" / "unused-live.png").write_bytes(b"x")
    assert curation.orphan_captures(docs_tree) == ["docs/images/unused-live.png"]


def test_the_repository_has_no_dangling_references_or_orphan_captures() -> None:
    assert curation.dangling_references(ROOT) == []
    assert curation.orphan_captures(ROOT) == []


def test_the_committed_manifest_lists_exactly_the_curated_set() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    assert sorted(entry["path"] for entry in manifest["screenshots"]) == curation.curated_capture_names(ROOT)


def test_the_capture_script_reads_the_same_curated_set() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    script = (
        "import('./ui/scripts/product-proof-curation.mjs')"
        ".then(m => m.curatedCaptureNames(process.cwd()))"
        ".then(names => { process.stdout.write(JSON.stringify(names)); });"
    )
    result = subprocess.run([node, "--input-type=module", "-e", script], cwd=ROOT, check=True, capture_output=True, text=True)
    assert json.loads(result.stdout) == curation.curated_capture_names(ROOT)
