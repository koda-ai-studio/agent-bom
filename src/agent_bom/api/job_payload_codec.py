"""Compress stored scan-job results behind a versioned, SQL-visible header.

A completed job's ``result`` (and any ``result_document`` rendering) is the
bulk of its row, and it was rewritten uncompressed on every job update. Large
values are stored as::

    {"__abom_codec": {"codec": "zstd", "encoding": "base64", "v": 1, "raw_bytes": N},
     "scan_sources": [...], "findings_count": n, "vulnerabilities_count": m,
     "data": "<base64 zstd of the JSON value>"}

The header keeps the job row valid JSON/JSONB, so top-level job columns and
``data->>'source_id'`` style predicates are untouched. SQL that reads inside a
stored result may only use ``SQL_PROJECTED_RESULT_KEYS``. Rows written before
compression, small values and ``None`` stay plain JSON and decode unchanged.
"""

from __future__ import annotations

import base64
import json
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator
from pydantic_core import to_json

from agent_bom.config import _str

RESULT_CODEC_KEY = "__abom_codec"
CODEC_VERSION = 1
MIN_COMPRESS_BYTES = 4096
_ZSTD_LEVEL = 3
# Keys SQL may read inside a stored result. ``findings``/``vulnerabilities``
# exist only on plain rows; compressed rows answer through the ``*_count`` keys.
SQL_PROJECTED_RESULT_KEYS = frozenset({"scan_sources", "findings", "vulnerabilities", "findings_count", "vulnerabilities_count"})


def _zstd() -> Any:
    try:
        import zstandard
    except ImportError:  # pragma: no cover - zstandard ships with the api extra
        return None
    return zstandard


def _list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def compression_enabled() -> bool:
    """``AGENT_BOM_JOB_RESULT_CODEC=none`` keeps new rows readable by older releases (read per write)."""
    return _str("AGENT_BOM_JOB_RESULT_CODEC", "zstd").strip().lower() != "none"


def encode_result_field(value: Any) -> Any:
    """Return the stored form of ``result``/``result_document``."""
    if value is None:
        return None
    raw = to_json(value)
    zstd = _zstd() if compression_enabled() else None
    if len(raw) < MIN_COMPRESS_BYTES or zstd is None:
        return json.loads(raw)
    header = {"codec": "zstd", "encoding": "base64", "v": CODEC_VERSION, "raw_bytes": len(raw)}
    envelope: dict[str, Any] = {RESULT_CODEC_KEY: header}
    if isinstance(value, dict):
        sources = value.get("scan_sources")
        envelope["scan_sources"] = list(sources) if isinstance(sources, list) else []
        envelope["findings_count"] = _list_len(value.get("findings"))
        envelope["vulnerabilities_count"] = _list_len(value.get("vulnerabilities"))
    envelope["data"] = base64.b64encode(zstd.ZstdCompressor(level=_ZSTD_LEVEL).compress(raw)).decode("ascii")
    return envelope


def decode_result_field(value: Any) -> Any:
    """Inverse of :func:`encode_result_field`; plain values pass through."""
    if not isinstance(value, dict) or RESULT_CODEC_KEY not in value:
        return value
    header = value[RESULT_CODEC_KEY]
    if not isinstance(header, dict) or header.get("v") != CODEC_VERSION or header.get("codec") != "zstd":
        raise ValueError(f"Unsupported stored job result codec version: {header!r}")
    zstd = _zstd()
    if zstd is None:  # pragma: no cover - zstandard ships with the api extra
        raise ValueError("Reading a compressed job result requires the zstandard package (agent-bom[api])")
    raw = zstd.ZstdDecompressor().decompress(base64.b64decode(value["data"]), max_output_size=int(header["raw_bytes"]))
    return json.loads(raw)


def encode_job_payload(job: BaseModel) -> str:
    """Serialize a ``ScanJob`` for storage with its result fields compressed."""
    payload = json.loads(job.model_dump_json(exclude={"result", "result_document"}))
    payload["result"] = encode_result_field(getattr(job, "result", None))
    payload["result_document"] = encode_result_field(getattr(job, "result_document", None))
    return json.dumps(payload, separators=(",", ":"))


StoredResult = Annotated[dict[str, Any] | None, BeforeValidator(decode_result_field)]
StoredResultDocument = Annotated[dict[str, Any] | str | None, BeforeValidator(decode_result_field)]
