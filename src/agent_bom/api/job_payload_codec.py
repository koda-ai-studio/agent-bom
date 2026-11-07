"""Compress stored scan-job results behind a versioned, SQL-visible header.

A completed job's ``result`` (and any ``result_document`` rendering) is the
bulk of its row, and it was rewritten uncompressed on every job update. Large
values are stored as::

    {"__abom_codec": {"codec": "zstd", "encoding": "base64", "v": 1, "raw_bytes": N},
     "scan_sources": [...], "findings_count": n, "vulnerabilities_count": m,
     "summary_projection": {"fields": {...}, "shape": [[key, kind, count], ...]},
     "data": "<base64 zstd of the JSON value>"}

The header keeps the job row valid JSON/JSONB, so top-level job columns and
``data->>'source_id'`` style predicates are untouched. SQL that reads inside a
stored result may only use ``SQL_PROJECTED_RESULT_KEYS``. Rows written before
compression, small values and ``None`` stay plain JSON and decode unchanged.

``summary_projection`` carries the small summary objects and the top-level
shape of a compressed result so the default job read can answer without
decompressing or parsing the whole document. It is derived from the same value
at write time; rows without it fall back to a full decode.
"""

from __future__ import annotations

import base64
import json
from typing import Annotated, Any

import zstandard
from pydantic import BaseModel, BeforeValidator
from pydantic_core import to_json

from agent_bom.api.payload_compression import decode_zstd_json
from agent_bom.config import _str

RESULT_CODEC_KEY = "__abom_codec"
CODEC_VERSION = 1
MIN_COMPRESS_BYTES = 4096
MAX_RESULT_BYTES = 256 * 1024 * 1024
_ZSTD_LEVEL = 3
# Keys SQL may read inside a stored result. ``findings``/``vulnerabilities``
# exist only on plain rows; compressed rows answer through the ``*_count`` keys.
# ``pushed`` also exists only on plain rows; compressed rows carry it in the projection.
RESULT_PROJECTION_KEY = "summary_projection"
SQL_PROJECTED_RESULT_KEYS = frozenset(
    {
        "scan_sources",
        "findings",
        "vulnerabilities",
        "findings_count",
        "vulnerabilities_count",
        "pushed",
        RESULT_CODEC_KEY,
        RESULT_PROJECTION_KEY,
    }
)
# Small result members the summary read returns inline; everything else is a section.
PROJECTED_RESULT_FIELDS = (
    "summary",
    "aggregation",
    "scan_run",
    "auto_correlation",
    "generated_at",
    "scan_timestamp",
    "scan_id",
    "pushed",
    "graph_persistence",
)
_WARNINGS_PREVIEW = 3


def _list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def result_shape(result: dict[str, Any]) -> list[list[Any]]:
    """``[key, kind, count]`` for every top-level member; ``count`` is set for lists."""
    shape: list[list[Any]] = []
    for key, value in result.items():
        if isinstance(value, list):
            shape.append([key, "list", len(value)])
        elif isinstance(value, dict):
            shape.append([key, "object", None])
        else:
            shape.append([key, "scalar", None])
    return shape


def result_summary_projection(result: dict[str, Any]) -> dict[str, Any]:
    """Bounded summary members plus the shape of ``result``; never the large sections."""
    fields = {key: result[key] for key in PROJECTED_RESULT_FIELDS if key in result}
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        fields["warnings"] = warnings[:_WARNINGS_PREVIEW]
        fields["warning_total"] = len(warnings)
    return {"fields": fields, "shape": result_shape(result)}


def compression_enabled() -> bool:
    """``AGENT_BOM_JOB_RESULT_CODEC=none`` keeps new rows readable by older releases (read per write)."""
    return _str("AGENT_BOM_JOB_RESULT_CODEC", "zstd").strip().lower() != "none"


def encode_result_field(value: Any, *, project: bool = False) -> Any:
    """Return the stored form of ``result``/``result_document``; ``project`` adds the summary projection."""
    if value is None:
        return None
    raw = to_json(value)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError("Stored job result exceeds the 256 MiB size limit")
    if len(raw) < MIN_COMPRESS_BYTES or not compression_enabled():
        return json.loads(raw)
    header = {"codec": "zstd", "encoding": "base64", "v": CODEC_VERSION, "raw_bytes": len(raw)}
    envelope: dict[str, Any] = {RESULT_CODEC_KEY: header}
    if isinstance(value, dict):
        sources = value.get("scan_sources")
        envelope["scan_sources"] = list(sources) if isinstance(sources, list) else []
        envelope["findings_count"] = _list_len(value.get("findings"))
        envelope["vulnerabilities_count"] = _list_len(value.get("vulnerabilities"))
        if project:
            envelope[RESULT_PROJECTION_KEY] = json.loads(to_json(result_summary_projection(value)))
    envelope["data"] = base64.b64encode(zstandard.ZstdCompressor(level=_ZSTD_LEVEL).compress(raw)).decode("ascii")
    return envelope


def decode_result_field(value: Any) -> Any:
    """Inverse of :func:`encode_result_field`; plain values pass through."""
    if not isinstance(value, dict) or RESULT_CODEC_KEY not in value:
        return value
    header = value[RESULT_CODEC_KEY]
    if not isinstance(header, dict) or header.get("v") != CODEC_VERSION or header.get("codec") != "zstd":
        raise ValueError("Unsupported stored job result codec version")
    if header.get("encoding") != "base64":
        raise ValueError("Unsupported stored job result encoding")
    size = header.get("raw_bytes")
    if type(size) is not int or size < 1:
        raise ValueError("Invalid stored job result size")
    if size > MAX_RESULT_BYTES:
        raise ValueError("Stored job result exceeds the 256 MiB size limit")
    return decode_zstd_json(value.get("data"), max_bytes=MAX_RESULT_BYTES, expected_size=size)


def encode_job_payload(job: BaseModel) -> str:
    """Serialize a ``ScanJob`` for storage with its result fields compressed."""
    payload = json.loads(job.model_dump_json(exclude={"result", "result_document"}))
    payload["result"] = encode_result_field(getattr(job, "result", None), project=True)
    payload["result_document"] = encode_result_field(getattr(job, "result_document", None))
    return json.dumps(payload, separators=(",", ":"))


StoredResult = Annotated[dict[str, Any] | None, BeforeValidator(decode_result_field)]
StoredResultDocument = Annotated[dict[str, Any] | str | None, BeforeValidator(decode_result_field)]
