"""PII-only projection of known numeric quantities in Next build manifests."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_SPACE = re.compile(r"\s*")
_DECODER = json.JSONDecoder()
_MAX_MANIFEST_BYTES = 1024 * 1024


def _members(content: str, start: int) -> Iterator[tuple[str, Any, int, int]]:
    """Yield direct object members and exact value spans in validated JSON."""
    index = _SPACE.match(content, start + 1).end()  # type: ignore[union-attr]
    while content[index] != "}":
        key, index = _DECODER.raw_decode(content, index)
        index = _SPACE.match(content, index).end()  # type: ignore[union-attr]
        value_start = _SPACE.match(content, index + 1).end()  # type: ignore[union-attr]
        value, end = _DECODER.raw_decode(content, value_start)
        yield key, value, value_start, end
        index = _SPACE.match(content, end).end()  # type: ignore[union-attr]
        if content[index] == ",":
            index = _SPACE.match(content, index + 1).end()  # type: ignore[union-attr]


def _numeric_spans(content: str, start: int, names: set[str]) -> list[tuple[int, int]]:
    return [(begin, end) for key, value, begin, end in _members(content, start) if key in names and type(value) is int and value >= 0]


def mask_build_config_quantities(content: str, file_path: Path) -> str:
    """Mask only known numeric config paths for PII matching; preserve offsets.

    Credentials are scanned separately against the original text. Other JSON
    fields, quoted values, invalid manifests and unknown files stay untouched.
    """
    if file_path.name != "required-server-files.json" or file_path.parent.name != ".next" or len(content) > _MAX_MANIFEST_BYTES:
        return content
    try:
        document = json.loads(content)
        if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != 1:
            return content
        root = _SPACE.match(content).end()  # type: ignore[union-attr]
        members = {key: (value, start) for key, value, start, _ in _members(content, root)}
        config, start = members.get("config", (None, 0))
        if not isinstance(config, dict):
            return content
        spans: list[tuple[int, int]] = []
        for key, value, begin, _ in _members(content, start):
            if not isinstance(value, dict):
                continue
            if key == "experimental":
                spans.extend(_numeric_spans(content, begin, {"imgOptMaxInputPixels", "turbopackStaleOutputMaxAge"}))
            elif key == "cacheLife":
                for _, profile, profile_start, _ in _members(content, begin):
                    if isinstance(profile, dict):
                        spans.extend(_numeric_spans(content, profile_start, {"expire"}))
    except (ValueError, RecursionError):
        return content
    parts: list[str] = []
    offset = 0
    for begin, end in sorted(spans):
        parts.extend((content[offset:begin], " " * (end - begin)))
        offset = end
    parts.append(content[offset:])
    return "".join(parts)
