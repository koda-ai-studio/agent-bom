"""Stored compressed evidence must not trust attacker-controlled size headers."""

from __future__ import annotations

import base64
import json

import pytest

from agent_bom.api import hub_payload_codec as hub
from agent_bom.api import job_payload_codec as job

zstd = pytest.importorskip("zstandard")


def _envelope(raw: bytes, *, content_size: bool = True, declared: object = None) -> dict:
    return {
        job.RESULT_CODEC_KEY: {"v": 1, "codec": "zstd", "encoding": "base64", "raw_bytes": len(raw) if declared is None else declared},
        "data": base64.b64encode(zstd.ZstdCompressor(write_content_size=content_size).compress(raw)).decode(),
    }


@pytest.mark.parametrize("content_size", [True, False])
def test_job_decode_enforces_absolute_output_limit(monkeypatch, content_size) -> None:
    monkeypatch.setattr(job, "MAX_RESULT_BYTES", 128, raising=False)
    payload = _envelope(json.dumps({"text": "x" * 1024}).encode(), content_size=content_size, declared=64)
    with pytest.raises(ValueError, match="limit"):
        job.decode_result_field(payload)


@pytest.mark.parametrize("declared", [1, 4096, True, -1, "128", None])
def test_job_decode_refuses_invalid_or_inaccurate_size(declared) -> None:
    payload = _envelope(b'{"value":42}')
    payload[job.RESULT_CODEC_KEY]["raw_bytes"] = declared
    with pytest.raises(ValueError, match="size"):
        job.decode_result_field(payload)


@pytest.mark.parametrize("content_size", [True, False])
def test_hub_decode_enforces_absolute_output_limit(monkeypatch, content_size) -> None:
    monkeypatch.setattr(hub, "MAX_HUB_PAYLOAD_BYTES", 128, raising=False)
    payload = _envelope(json.dumps({"text": "x" * 1024}).encode(), content_size=content_size)
    wrapper = {"__abom_zstd": True, "v": 1, "data": payload["data"]}
    with pytest.raises(ValueError, match="limit"):
        hub.decode_hub_payload(wrapper)


@pytest.mark.parametrize("data", [None, "!not-base64!", base64.b64encode(b"not-zstd").decode()])
@pytest.mark.parametrize("codec", ["job", "hub"])
def test_corrupt_compressed_rows_raise_validation_errors(data, codec) -> None:
    payload = _envelope(b'{"value":42}')
    payload["data"] = data
    if codec == "hub":
        payload = {"__abom_zstd": True, "v": 1, "data": data}
    with pytest.raises(ValueError, match="compressed payload"):
        (job.decode_result_field if codec == "job" else hub.decode_hub_payload)(payload)


@pytest.mark.parametrize("codec", ["job", "hub"])
def test_encoding_refuses_values_the_decoder_cannot_read(monkeypatch, codec) -> None:
    module, limit, encode = (
        (job, "MAX_RESULT_BYTES", job.encode_result_field) if codec == "job" else (hub, "MAX_HUB_PAYLOAD_BYTES", hub.encode_hub_payload)
    )
    monkeypatch.setattr(module, limit, 128, raising=False)
    with pytest.raises(ValueError, match="limit"):
        encode({"text": "x" * 1024})


def test_concatenated_frames_cannot_hide_extra_decoded_bytes(monkeypatch) -> None:
    monkeypatch.setattr(job, "MAX_RESULT_BYTES", 128, raising=False)
    payload = _envelope(b'{"value":42}')
    compressed = base64.b64decode(payload["data"]) + zstd.ZstdCompressor().compress(b" " * 1024)
    payload["data"] = base64.b64encode(compressed).decode()
    with pytest.raises(ValueError, match="limit|size"):
        job.decode_result_field(payload)


@pytest.mark.parametrize("codec", ["job", "hub"])
def test_truncated_frames_are_not_accepted_as_partial_evidence(codec) -> None:
    payload = _envelope(b'{"value":42}')
    payload["data"] = base64.b64encode(base64.b64decode(payload["data"])[:-1]).decode()
    if codec == "hub":
        payload = {"__abom_zstd": True, "v": 1, "data": payload["data"]}
    with pytest.raises(ValueError, match="compressed payload"):
        (job.decode_result_field if codec == "job" else hub.decode_hub_payload)(payload)


@pytest.mark.parametrize("content_size", [True, False])
def test_exact_output_limit_is_accepted(monkeypatch, content_size) -> None:
    raw = b'{"value":42}'
    monkeypatch.setattr(job, "MAX_RESULT_BYTES", len(raw), raising=False)
    monkeypatch.setattr(hub, "MAX_HUB_PAYLOAD_BYTES", len(raw), raising=False)
    payload = _envelope(raw, content_size=content_size)
    assert job.decode_result_field(payload) == {"value": 42}
    assert hub.decode_hub_payload({"__abom_zstd": True, "v": 1, "data": payload["data"]}) == {"value": 42}
