"""Bounded decoding for the single-frame zstd envelopes stored by the API."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from pydantic_core import from_json

MAX_WINDOW_BYTES = 16 * 1024 * 1024


def decode_zstd_json(encoded: object, *, max_bytes: int, expected_size: int | None = None) -> Any:
    """Reject oversized frames before allocation, unknown-size bombs and trailing data."""
    import zstandard as zstd

    # A zstd frame may be slightly larger than its input. Bound the base64 text
    # before allocating decoded bytes, while allowing encoder framing overhead.
    max_encoded = 4 * ((max_bytes + 64 * 1024 + 2) // 3)
    if not isinstance(encoded, str) or len(encoded) > max_encoded:
        raise ValueError("Invalid compressed payload or encoded size limit exceeded")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        params = zstd.get_frame_parameters(compressed)
        if params.content_size != zstd.CONTENTSIZE_UNKNOWN and params.content_size > max_bytes:
            raise ValueError("Compressed payload exceeds the decompressed size limit")
        if params.window_size > MAX_WINDOW_BYTES:
            raise ValueError("Compressed payload exceeds the decompression window limit")
        # max_output_size alone is ignored when a frame declares its size:
        # that case is checked above, before zstd allocates its output buffer.
        raw = zstd.ZstdDecompressor(max_window_size=MAX_WINDOW_BYTES // 1024).decompress(
            compressed, max_output_size=max_bytes, allow_extra_data=False
        )
    except (binascii.Error, zstd.ZstdError, UnicodeEncodeError) as exc:
        raise ValueError("Invalid compressed payload or decompression limit exceeded") from exc
    if expected_size is not None and len(raw) != expected_size:
        raise ValueError("Stored compressed payload size does not match its header")
    try:
        # Parse bytes directly and reuse repeated immutable strings (package
        # names, severities, control identifiers). The stdlib first allocates
        # a full Unicode copy and then a new string for every repeated value.
        # Dicts/lists remain independent; this is not a cached evidence result.
        return from_json(raw, cache_strings=True, allow_partial=False)
    except ValueError:
        # Older stored JSON can contain stdlib-supported encodings, escaped
        # lone surrogates or nesting beyond the fast parser's depth limit.
        # Preserve readability without changing the on-disk codec contract.
        pass
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid compressed payload JSON") from exc
