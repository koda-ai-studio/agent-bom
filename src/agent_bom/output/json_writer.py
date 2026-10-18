"""Write large JSON report documents quickly with bounded peak memory."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, TextIO, cast


def write_json_file(data: dict[str, Any], output_path: str) -> None:
    """Publish a complete JSON file by same-directory replacement.

    Encoding, write, flush and replacement failures leave an existing report
    intact. Resolve links to preserve the existing export's symlink behavior.
    New files are private; replacements preserve the destination's mode bits.
    This protects publication, not directory durability across power loss.
    """
    target = Path(output_path).resolve()
    if target == Path(os.devnull).resolve():
        # Null sinks preserve scan verdicts and never replace a device node.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            write_json_document(data, sink)
        return
    if target.exists() and not target.is_file():
        raise ValueError("JSON report destination must be a regular file")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, prefix=".agent-bom-json-", delete=False) as fh:
            temporary = Path(fh.name)
            write_json_document(data, cast(TextIO, fh))
            fh.flush()
            os.fsync(fh.fileno())
        if target.exists():
            temporary.chmod(stat.S_IMODE(target.stat().st_mode))
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json_document(data: dict[str, Any], fh: TextIO) -> None:
    """Write exactly ``json.dump(data, fh, indent=2)`` followed by a newline.

    ``json.dump`` always runs the pure-Python encoder; ``json.dumps`` uses the C
    encoder. Encoding each top-level member separately keeps that speed while
    holding only the largest section in memory rather than the whole document.
    """
    if not data:
        fh.write(json.dumps(data, indent=2) + "\n")
        return
    fh.write("{\n")
    for index, (key, value) in enumerate(data.items()):
        if index:
            fh.write(",\n")
        # ``{"k": v}`` at indent=2 renders the member exactly as it appears in
        # the full document; strip the enclosing "{\n" and "\n}".
        fh.write(json.dumps({key: value}, indent=2)[2:-2])
    fh.write("\n}\n")
