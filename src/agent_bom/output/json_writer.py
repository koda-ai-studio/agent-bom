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
_COMPACT_SEPARATORS = (",", ":")
# A container with more nested elements than this is written member by member;
# anything smaller is encoded in one ``json.dumps`` call.
_STREAM_THRESHOLD = 512
_CONTAINERS = (dict, list, tuple, set)

# ``expand(value, context)`` decides how one value is written: ("value", obj)
# encodes ``obj`` whole; ("object", [(key, child, child_context), ...]) and
# ("array", [(child, child_context), ...]) stream the container's members.
Expand = Callable[[Any, Any], tuple[str, Any]]


def is_gzip_path(output_path: str) -> bool:
    return output_path.lower().endswith(".gz")


def write_json_file(
    data: dict[str, Any], output_path: str, *, compact: bool = False, expand: Expand | None = None, context: Any = None
) -> None:
    """Publish a complete JSON file by same-directory replacement.

    Encoding, write, flush and replacement failures leave an existing report
    intact. Resolve links to preserve the existing export's symlink behavior.
    New files are private; replacements preserve the destination's mode bits.
    This protects publication, not directory durability across power loss.
    A ``.gz`` destination receives a deterministic gzip stream (no name or
    timestamp in the header) written as the document is encoded. ``expand``
    and ``context`` are passed to the document writer.
    """
    document_writer = write_compact_json_document if compact else write_json_document
    options: dict[str, Any] = {} if expand is None else {"expand": expand, "context": context}

    def writer(document: dict[str, Any], fh: TextIO) -> None:
        document_writer(document, fh, **options)

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


def is_large_container(value: object, threshold: int = _STREAM_THRESHOLD) -> bool:
    """True when ``value`` nests more than ``threshold`` elements (stops counting early)."""
    if not isinstance(value, _CONTAINERS):
        return False
    budget = threshold
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        budget -= len(item)
        if budget < 0:
            return True
        children = item.values() if isinstance(item, dict) else item
        stack.extend(child for child in children if isinstance(child, _CONTAINERS) and child)
    return False


def streams_container(value: object, depth: int) -> bool:
    """Write ``value`` member by member: the root object, every top-level list, and any large container.

    Top-level lists (report sections such as findings) stream item by item even
    when they hold few elements, since each item can carry large strings.
    """
    if depth == 0 and isinstance(value, dict):
        return True
    return (depth == 1 and isinstance(value, list) and bool(value)) or is_large_container(value)


def plain_expand(value: Any, context: Any = None) -> tuple[str, Any]:
    """Stream JSON-native containers exactly as ``json.dumps`` would render them; ``context`` is the depth."""
    depth = int(context or 0)
    if type(value) is dict and streams_container(value, depth) and all(type(key) is str for key in value):
        return "object", ((key, child, depth + 1) for key, child in value.items())
    if type(value) in (list, tuple) and streams_container(value, depth):
        return "array", ((child, depth + 1) for child in value)
    return "value", value


def write_json_document(
    data: dict[str, Any], fh: TextIO, *, expand: Expand = plain_expand, context: Any = None, newline: bool = True
) -> None:
    """Write exactly ``json.dump(data, fh, indent=2)``, followed by a newline unless ``newline`` is false.

    ``json.dump`` always runs the pure-Python encoder; ``json.dumps`` uses the C
    encoder but materializes every chunk of its input before joining them.
    Large containers, at any depth, are therefore written member by member and
    only small subtrees go through ``json.dumps``, so peak memory tracks the
    largest small subtree rather than the largest report section. ``expand``
    may transform values on the way out (for example, redaction) without
    building a copy of the document.
    """
    _write_value(fh, data, context, expand, 0, compact=False)
    if newline:
        fh.write("\n")


def write_compact_json_document(data: dict[str, Any], fh: TextIO, *, expand: Expand = plain_expand, context: Any = None) -> None:
    """Write exactly ``json.dumps(data, separators=(",", ":"))``, streamed the same way."""
    _write_value(fh, data, context, expand, 0, compact=True)


def _encode(value: Any, level: int, *, compact: bool) -> str:
    if compact:
        return json.dumps(value, separators=_COMPACT_SEPARATORS)
    text = json.dumps(value, indent=2)
    return text.replace("\n", "\n" + _INDENT * level) if level and "\n" in text else text


def _write_value(fh: TextIO, value: Any, context: Any, expand: Expand, level: int, *, compact: bool) -> None:
    kind, body = expand(value, context)
    if kind == "value":
        fh.write(_encode(body, level, compact=compact))
        return
    is_object = kind == "object"
    opener, closer = ("{", "}") if is_object else ("[", "]")
    separator = "" if compact else "\n" + _INDENT * (level + 1)
    key_separator = ":" if compact else ": "
    wrote = False
    for entry in body:
        fh.write((opener if not wrote else ",") + separator)
        wrote = True
        if is_object:
            key, child, child_context = entry
            if type(key) is not str:
                raise TypeError(f"streamed JSON object keys must be str, not {type(key).__name__}")
            fh.write(json.dumps(key) + key_separator)
        else:
            child, child_context = entry
        _write_value(fh, child, child_context, expand, level + 1, compact=compact)
    if not wrote:
        fh.write(opener + closer)
    else:
        fh.write(closer if compact else "\n" + _INDENT * level + closer)
