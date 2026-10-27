"""Bounded content classification for model and Python startup files."""

from __future__ import annotations

import ast
from pathlib import Path

MAX_STARTUP_BYTES = 65536


def is_python_startup_text(data: bytes) -> bool:
    """Recognize a complete, bounded import-only .pth file without executing it.

    Ambiguous paths, binary streams and malformed/trailing payloads stay on the
    model scanner path. This classifies syntax; it does not attest safe Python.
    """
    if not data or len(data) > MAX_STARTUP_BYTES:
        return False
    try:
        text = data.decode("utf-8")
        if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
            return False
        imports = 0
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            if not line.startswith(("import ", "import\t")):
                return False
            statements = ast.parse(line).body
            if not statements or not isinstance(statements[0], ast.Import):
                return False
            imports += 1
        return imports > 0
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
        return False


def is_python_startup_file(path: Path) -> bool:
    if path.suffix.lower() != ".pth":
        return False
    try:
        with path.open("rb") as stream:
            return is_python_startup_text(stream.read(MAX_STARTUP_BYTES + 1))
    except OSError:
        return False


_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
# Pickle protocol-2+ streams begin with the PROTO opcode (0x80) followed by a
# one-byte protocol number (1..5). Higher protocols (5) cover modern torch.
_PICKLE_PROTOCOLS = frozenset({1, 2, 3, 4, 5})


def _looks_like_pickle_header(file_path: Path) -> bool:
    """Cheap content sniff: does this file *start* like a pickle or torch zip?

    Reads only the first few bytes (no deserialization, bounded I/O). Used to
    discover pickle-bearing content hiding under a benign or non-pickle-bearing
    extension, which extension-only discovery would miss entirely.
    """
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    if not head:
        return False
    if head[:4] in _ZIP_MAGICS:
        return True
    return head[:1] == b"\x80" and len(head) >= 2 and head[1] in _PICKLE_PROTOCOLS
