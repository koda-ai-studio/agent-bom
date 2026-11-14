"""Stream the ``GET /v1/scan/{job_id}?view=full`` body of a large job.

The bytes equal :func:`agent_bom.api.scan_job_detail.full_body`: the job is
redacted the same way, every field except ``result`` comes from the same
``ScanJob`` serializers, and ``result`` is encoded member by member with the
same encoder, so no body-sized buffer is built. Small jobs keep the one-shot
body.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pydantic_core import to_json

from agent_bom.api.models import ScanJob
from agent_bom.api.scan_job_views import _job_response_payload
from agent_bom.output.json_writer import is_large_container, streams_container

# Nested values in ``result`` above which the full view is streamed.
STREAM_MIN_ELEMENTS = 20_000
_CHUNK_BYTES = 64 * 1024


def streams_full_body(job: ScanJob) -> bool:
    return is_large_container(job.result, STREAM_MIN_ELEMENTS)


def full_body_chunks(job: ScanJob) -> Iterator[bytes]:
    """The redacted full job as JSON in chunks of at most ~64 KiB beyond one encoded leaf."""
    return redacted_body_chunks(_job_response_payload(job))


def redacted_body_chunks(payload: ScanJob) -> Iterator[bytes]:
    """Encode an already redacted job (from ``_job_response_payload``) in chunks."""
    shell = payload.model_copy(update={"result": None})
    fields = shell.__pydantic_serializer__.to_python(shell, mode="json")
    buffer = bytearray()
    for piece in _object_pieces(fields, payload.result):
        buffer += piece
        if len(buffer) >= _CHUNK_BYTES:
            yield bytes(buffer)
            buffer.clear()
    if buffer:
        yield bytes(buffer)


def _object_pieces(fields: dict[str, Any], result: Any) -> Iterator[bytes]:
    first = True
    for key, value in fields.items():
        yield (b"{" if first else b",") + to_json(key) + b":"
        first = False
        if key == "result":
            yield from _value_pieces(result, 0)
        else:
            yield to_json(value)
    yield b"{}" if first else b"}"


def _value_pieces(value: Any, depth: int) -> Iterator[bytes]:
    if type(value) is dict and streams_container(value, depth) and all(type(key) is str for key in value):
        if not value:
            yield b"{}"
            return
        opener = b"{"
        for key, child in value.items():
            yield opener + to_json(key) + b":"
            opener = b","
            yield from _value_pieces(child, depth + 1)
        yield b"}"
        return
    if type(value) is list and streams_container(value, depth):
        opener = b"["
        for child in value:
            yield opener
            opener = b","
            yield from _value_pieces(child, depth + 1)
        yield b"[]" if opener == b"[" else b"]"
        return
    yield to_json(value)
