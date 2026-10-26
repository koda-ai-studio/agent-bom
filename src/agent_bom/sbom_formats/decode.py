"""Turn raw SBOM bytes into the JSON-shaped document every reader consumes."""

from __future__ import annotations

import gzip
import io
import json
from collections.abc import Callable
from typing import Any

from agent_bom.sbom_formats.cyclonedx_xml import cyclonedx_xml_to_document
from agent_bom.sbom_formats.spdx_tagvalue import is_spdx_tagvalue, spdx_tagvalue_to_document

MAX_SBOM_BYTES = 10 * 1024 * 1024
GZIP_MAGIC = b"\x1f\x8b"


def _text(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw.removeprefix("﻿")
    # Same UTF-8/16/32 detection json.loads applies to bytes, so documents
    # redirected by shells that write UTF-16 keep loading.
    try:
        return raw.decode(json.detect_encoding(raw)).removeprefix("﻿")
    except UnicodeDecodeError as exc:
        raise ValueError("SBOM must be UTF-8, UTF-16 or UTF-32 encoded") from exc


def sbom_serialization(raw: bytes | str) -> str:
    """Classify the serialization: ``json``, ``cyclonedx-xml`` or ``spdx-tag-value``.

    Accepts a leading slice of a file; a truncated trailing character is ignored.
    """
    text = raw.decode(json.detect_encoding(raw), errors="ignore").removeprefix("﻿") if isinstance(raw, bytes) else raw
    head = text.lstrip()
    if head.startswith("<"):
        return "cyclonedx-xml"
    if is_spdx_tagvalue(text):
        return "spdx-tag-value"
    return "json"


def gunzip_bounded(raw: bytes, limit: int = MAX_SBOM_BYTES) -> bytes:
    """Inflate a gzip member, refusing output above ``limit`` bytes."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            inflated = stream.read(limit + 1)
    except (OSError, EOFError) as exc:
        raise ValueError("SBOM is not a valid gzip stream") from exc
    if len(inflated) > limit:
        raise ValueError("SBOM exceeds the 10 MiB import limit once decompressed")
    return inflated


def decode_sbom_document(raw: bytes | str, json_loader: Callable[[str], Any] = json.loads) -> Any:
    """Decode CycloneDX JSON/XML or SPDX JSON/tag-value into one JSON shape.

    Inputs above ``MAX_SBOM_BYTES`` are refused before parsing, and gzip input
    is inflated only up to that limit. JSON goes through ``json_loader`` so
    callers keep their strictness rules.
    """
    if isinstance(raw, bytes) and raw[:2] == GZIP_MAGIC:
        raw = gunzip_bounded(raw)
    size = len(raw.encode("utf-8") if isinstance(raw, str) else raw)
    if size > MAX_SBOM_BYTES:
        raise ValueError("SBOM exceeds the 10 MiB import limit")
    text = _text(raw)
    kind = sbom_serialization(text)
    if kind == "cyclonedx-xml":
        return cyclonedx_xml_to_document(text.encode("utf-8"))
    if kind == "spdx-tag-value":
        return spdx_tagvalue_to_document(text)
    return json_loader(text)
