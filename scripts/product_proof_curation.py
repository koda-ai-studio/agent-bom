"""Derive the committed product-proof screenshot set from the published docs.

A capture is committed only when README.md, docs/ or site-docs/ embeds or links
it. Mirrored in ui/scripts/product-proof-curation.mjs, which the capture script
uses to decide what to capture; keep both in sync.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

IMAGE_DIR = "docs/images"
MARKDOWN_ROOTS = ("README.md", "docs", "site-docs")
# Referenced or committed rasters that the product-proof capture does not produce.
NON_CAPTURE_IMAGES = frozenset(
    {
        "demo-latest.gif",  # rendered from docs/demo.tape
        "social-preview.png",  # GitHub social preview, rendered by ui/scripts/render-brand-assets.mjs
    }
)

_MARKDOWN_TARGET = re.compile(r"\]\(\s*<?([^)\s>]+)")
_HTML_TARGET = re.compile(r"\b(?:src|srcset|href)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def markdown_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for entry in MARKDOWN_ROOTS:
        path = root / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(p for p in path.rglob("*.md") if p.is_file()))
    return files


def _targets(text: str) -> list[str]:
    targets = [match.group(1) for match in _MARKDOWN_TARGET.finditer(text)]
    for match in _HTML_TARGET.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        targets.extend(part.split()[0] for part in value.split(",") if part.strip())
    return targets


def _image_name(document: str, target: str) -> str | None:
    target = re.split(r"[?#]", target, maxsplit=1)[0]
    if "://" in target:
        marker = f"/{IMAGE_DIR}/"
        return target.split(marker, 1)[1] if marker in target else None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(document), target))
    prefix = f"{IMAGE_DIR}/"
    return resolved[len(prefix) :] if resolved.startswith(prefix) else None


def image_references(root: Path) -> dict[str, set[str]]:
    """Map each referenced docs/images path to the markdown files that use it."""
    references: dict[str, set[str]] = {}
    for path in markdown_files(root):
        document = path.relative_to(root).as_posix()
        for target in _targets(path.read_text(encoding="utf-8", errors="ignore")):
            name = _image_name(document, target)
            if name:
                references.setdefault(name, set()).add(document)
    return references


def _is_capture_name(name: str) -> bool:
    return "/" not in name and name.endswith(".png") and name not in NON_CAPTURE_IMAGES


def curated_capture_names(root: Path) -> list[str]:
    return sorted(name for name in image_references(root) if _is_capture_name(name))


def dangling_references(root: Path) -> list[str]:
    image_dir = root / IMAGE_DIR
    return sorted(
        f"{document} -> {IMAGE_DIR}/{name}"
        for name, documents in image_references(root).items()
        if not (image_dir / name).is_file()
        for document in documents
    )


def orphan_captures(root: Path) -> list[str]:
    curated = set(curated_capture_names(root))
    image_dir = root / IMAGE_DIR
    return sorted(
        f"{IMAGE_DIR}/{path.name}" for path in image_dir.glob("*.png") if _is_capture_name(path.name) and path.name not in curated
    )
