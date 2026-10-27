"""Encode/decode compliance-hub finding payloads at rest."""

from __future__ import annotations

import base64
import json
from typing import Any

from agent_bom.api.payload_compression import decode_zstd_json

_MARKER = "__abom_zstd"
_MIN_COMPRESS_BYTES = 512
_ZSTD_LEVEL = 3
MAX_HUB_PAYLOAD_BYTES = 16 * 1024 * 1024


def encode_hub_payload(payload: dict[str, Any]) -> str:
    """Serialize a finding payload, zstd-compressing when worthwhile."""
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    if len(raw) > MAX_HUB_PAYLOAD_BYTES:
        raise ValueError("Stored hub payload exceeds the 16 MiB size limit")
    if len(raw) < _MIN_COMPRESS_BYTES:
        return raw.decode("utf-8")
    import zstandard as zstd

    compressed = zstd.ZstdCompressor(level=_ZSTD_LEVEL).compress(raw)
    wrapper = {
        _MARKER: True,
        "v": 1,
        "data": base64.b64encode(compressed).decode("ascii"),
    }
    return json.dumps(wrapper, sort_keys=True)


def decode_hub_payload(stored: Any) -> dict[str, Any]:
    """Deserialize a hub payload from plain JSON or a zstd wrapper."""
    if isinstance(stored, dict):
        if stored.get(_MARKER):
            return _decode_wrapper(stored)
        return dict(stored)
    if stored is None:
        return {}
    text = stored if isinstance(stored, str) else str(stored)
    parsed = json.loads(text)
    if isinstance(parsed, dict) and parsed.get(_MARKER):
        return _decode_wrapper(parsed)
    return dict(parsed) if isinstance(parsed, dict) else {}


def _decode_wrapper(wrapper: dict[str, Any]) -> dict[str, Any]:
    if wrapper.get("v") != 1:
        raise ValueError("Unsupported stored hub payload codec version")
    parsed = decode_zstd_json(wrapper.get("data"), max_bytes=MAX_HUB_PAYLOAD_BYTES)
    if not isinstance(parsed, dict):
        raise ValueError("Invalid compressed payload: hub evidence must be an object")
    return parsed
