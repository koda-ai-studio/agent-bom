"""Large retained reports decode without duplicating every repeated scalar."""

from __future__ import annotations

import base64
import gc
import json
import tracemalloc

import pytest

from agent_bom.api.payload_compression import decode_zstd_json

zstd = pytest.importorskip("zstandard")


def _encoded(raw: bytes) -> str:
    return base64.b64encode(zstd.ZstdCompressor().compress(raw)).decode("ascii")


def _peak(load):
    gc.collect()
    tracemalloc.start()
    try:
        value = load()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return value, peak


def test_repeated_evidence_decodes_below_plain_json_allocation_budget():
    # Repeated package/control fields occur throughout retained scan reports.
    # Compare allocations, not host-dependent elapsed time. Both measurements
    # retain the complete decoded result; the codec also pays for decompression.
    raw = json.dumps(
        [{"package": "example-package", "severity": "critical", "source": "retained_scan", "version": "1.2.3"}] * 20_000
    ).encode()
    encoded = _encoded(raw)
    expected, plain_peak = _peak(lambda: json.loads(raw))
    actual, codec_peak = _peak(lambda: decode_zstd_json(encoded, max_bytes=len(raw), expected_size=len(raw)))
    assert actual == expected
    assert codec_peak < plain_peak * 0.8, (codec_peak, plain_peak)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"same": 1, "same": 2, "number": 123456789012345678901234567890, "float": 1.2345678901234567}',
        '{"unicode":"\u00e9\U0001f680","escaped":"\\n\\t","empty":[],"null":null}'.encode(),
        b'{"legacy_surrogate":"\\ud800"}',
        b"[" * 250 + b"0" + b"]" * 250,
        '{"legacy_encoding": true}'.encode("utf-16"),
    ],
)
def test_existing_json_values_remain_readable(raw):
    assert decode_zstd_json(_encoded(raw), max_bytes=len(raw)) == json.loads(raw)


@pytest.mark.parametrize("raw", [b'{"partial":', b'{"ok": 1} trailing', b'{"value": "\xff"}', b'{"bad": 01}'])
def test_invalid_json_never_becomes_partial_evidence(raw):
    with pytest.raises(ValueError, match="Invalid compressed payload JSON"):
        decode_zstd_json(_encoded(raw), max_bytes=len(raw))


def test_decodes_never_share_mutable_evidence():
    raw = b'{"rows":[{"severity":"high","values":[1,2]}]}'
    encoded = _encoded(raw)
    first = decode_zstd_json(encoded, max_bytes=len(raw))
    second = decode_zstd_json(encoded, max_bytes=len(raw))
    first["rows"][0]["values"].append(3)
    first["rows"][0]["severity"] = "low"
    assert second == json.loads(raw)
