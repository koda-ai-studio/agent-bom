"""Write large JSON report documents quickly with bounded peak memory."""

from __future__ import annotations

import gzip
import io
import json
import os
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO, TextIO, cast

_INDENT = "  "


def is_gzip_path(output_path: str) -> bool:
    return output_path.lower().endswith(".gz")


def write_json_file(data: dict[str, Any], output_path: str, *, compact: bool = False) -> None:
    """Publish a complete JSON file by same-directory replacement.

    Encoding, write, flush and replacement failures leave an existing report
    intact. Resolve links to preserve the existing export's symlink behavior.
    New files are private; replacements preserve the destination's mode bits.
    This protects publication, not directory durability across power loss.
    A ``.gz`` destination receives a deterministic gzip stream (no name or
    timestamp in the header) written as the document is encoded.
    """
    writer: Callable[[dict[str, Any], TextIO], None] = write_compact_json_document if compact else write_json_document
    target = Path(output_path).resolve()
    if target == Path(os.devnull).resolve():
        # Null sinks preserve scan verdicts and never replace a device node.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            writer(data, sink)
        return
    if target.exists() and not target.is_file():
        raise ValueError("JSON report destination must be a regular file")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, prefix=".agent-bom-json-", delete=False) as raw:
            temporary = Path(raw.name)
            _write_encoded(data, cast(BinaryIO, raw), writer, gzip_output=is_gzip_path(output_path))
            raw.flush()
            os.fsync(raw.fileno())
        if target.exists():
            temporary.chmod(stat.S_IMODE(target.stat().st_mode))
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_encoded(data: dict[str, Any], raw: BinaryIO, writer: Callable[[dict[str, Any], TextIO], None], *, gzip_output: bool) -> None:
    sink: BinaryIO = cast(BinaryIO, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)) if gzip_output else raw
    text = io.TextIOWrapper(sink, encoding="utf-8", newline="", write_through=False)
    try:
        writer(data, cast(TextIO, text))
        text.flush()
    finally:
        text.detach()
        if gzip_output:
            sink.close()


def _member(key: str, value: Any, *, compact: bool) -> str:
    """Render ``"key": value`` exactly as it appears inside the parent object."""
    if compact:
        return json.dumps({key: value}, separators=(",", ":"))[1:-1]
    return json.dumps({key: value}, indent=2)[2:-2]


def _write_list_member(fh: TextIO, key: str, items: list[Any], *, compact: bool) -> None:
    """Encode a top-level list one item at a time; output equals the whole-list rendering."""
    if compact:
        fh.write(json.dumps(key) + ":[")
        for index, item in enumerate(items):
            fh.write(("," if index else "") + json.dumps(item, separators=(",", ":")))
        fh.write("]")
        return
    fh.write(f"{_INDENT}{json.dumps(key)}: [\n")
    for index, item in enumerate(items):
        if index:
            fh.write(",\n")
        fh.write("\n".join(_INDENT * 2 + line for line in json.dumps(item, indent=2).split("\n")))
    fh.write(f"\n{_INDENT}]")


def _write_document(data: dict[str, Any], fh: TextIO, *, compact: bool) -> None:
    if not data:
        fh.write("{}" if compact else "{}\n")
        return
    fh.write("{" if compact else "{\n")
    for index, (key, value) in enumerate(data.items()):
        if index:
            fh.write("," if compact else ",\n")
        if isinstance(value, list) and value and isinstance(key, str):
            _write_list_member(fh, key, value, compact=compact)
        else:
            fh.write(_member(key, value, compact=compact))
    fh.write("}" if compact else "\n}\n")


def write_json_document(data: dict[str, Any], fh: TextIO) -> None:
    """Write exactly ``json.dump(data, fh, indent=2)`` followed by a newline.

    ``json.dump`` always runs the pure-Python encoder; ``json.dumps`` uses the C
    encoder. Encoding top-level members separately, and the items of top-level
    lists one at a time, keeps that speed while holding only the largest item
    in memory rather than the whole document.
    """
    _write_document(data, fh, compact=False)


def write_compact_json_document(data: dict[str, Any], fh: TextIO) -> None:
    """Write exactly ``json.dumps(data, separators=(",", ":"))``, streamed the same way."""
    _write_document(data, fh, compact=True)
