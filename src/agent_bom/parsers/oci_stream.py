"""Bounded-memory, bounded-time access to OCI image layers.

A layer is never buffered in RAM. An uncompressed layer on a seekable source
is read in place; anything else is decompressed in fixed-size chunks into an
anonymous temporary file while the size, decompression-ratio and wall-clock
limits are enforced on the bytes actually produced, so a decompression bomb is
abandoned at the limit instead of being expanded first and measured after.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO

from agent_bom.parsers.oci_io import (
    _decompression_ratio_exceeded,
    _max_decompression_ratio,
    _max_layer_members,
    _max_layer_uncompressed_bytes,
    _scan_timeout_seconds,
)

_CHUNK_BYTES = 1024 * 1024
_SEEKABLE_SOURCES = (io.BufferedReader, io.FileIO, io.BytesIO)

TIME_BUDGET_REASON = "oci_scan_time_budget"
TIME_BUDGET_DETAIL = "Image scan time budget was exhausted before this layer was fully read; image inventory is incomplete."


class LayerLimitError(Exception):
    """A layer crossed a safety bound and must be reported as a coverage gap."""

    def __init__(self, reason: str, detail: str, bytes_written: int = 0) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.bytes_written = bytes_written


@dataclass
class ScanBudget:
    """Wall-clock budget shared by every layer of one image scan."""

    seconds: float | None
    started: float = field(default_factory=time.monotonic)

    @classmethod
    def from_env(cls) -> ScanBudget:
        return cls(_scan_timeout_seconds())

    def expired(self) -> bool:
        return self.seconds is not None and time.monotonic() - self.started >= self.seconds

    def check(self, written: int = 0) -> None:
        if self.expired():
            raise LayerLimitError(TIME_BUDGET_REASON, TIME_BUDGET_DETAIL, written)


def _is_compressed(head: bytes) -> bool:
    return head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"))


def _decompressing_reader(source: IO[bytes], head: bytes) -> io.BufferedIOBase | None:
    if head.startswith(b"\x1f\x8b"):
        return gzip.GzipFile(fileobj=source, mode="rb")
    if head.startswith(b"BZh"):
        return bz2.BZ2File(source)
    if head.startswith(b"\xfd7zXZ\x00"):
        return lzma.LZMAFile(source)
    return None


def _write_limit(compressed_size: int, compressed: bool) -> tuple[int, str]:
    size_limit = _max_layer_uncompressed_bytes()
    if compressed and compressed_size > 0:
        ratio_limit = compressed_size * _max_decompression_ratio()
        if ratio_limit < size_limit:
            return ratio_limit, "oci_layer_decompression_limit"
    return size_limit, "oci_layer_size_limit"


_LIMIT_DETAILS = {
    "oci_layer_size_limit": "Container layer exceeds the uncompressed safety limit; image inventory is incomplete.",
    "oci_layer_decompression_limit": "Container layer exceeds the decompression-ratio safety limit; image inventory is incomplete.",
}


def _sniff(source: IO[bytes]) -> bytes:
    """Return the first bytes of ``source`` without consuming them."""
    peek = getattr(source, "peek", None)
    if peek is not None:
        return bytes(peek(6)[:6])
    head = source.read(6)
    source.seek(0)
    return head


def spool_layer(source: IO[bytes], compressed_size: int, budget: ScanBudget) -> IO[bytes]:
    """Copy (and decompress) ``source`` into a temporary file, chunk by chunk.

    Raises :class:`LayerLimitError` as soon as the produced bytes cross the
    uncompressed-size or decompression-ratio limit, or the scan budget runs
    out. The caller owns (and must close) the returned file.
    """
    reader = _decompressing_reader(source, _sniff(source))
    stream: IO[bytes] | io.BufferedIOBase = reader if reader is not None else source
    limit, reason = _write_limit(compressed_size, reader is not None)
    spool = tempfile.TemporaryFile()
    written = 0
    try:
        while chunk := stream.read(_CHUNK_BYTES):
            written += len(chunk)
            if written > limit:
                raise LayerLimitError(reason, _LIMIT_DETAILS[reason], written)
            budget.check(written)
            spool.write(chunk)
        spool.seek(0)
        return spool
    except BaseException:
        spool.close()
        raise


def _is_cheaply_seekable(source: IO[bytes], outer: object | None) -> bool:
    base = outer if outer is not None else source
    return isinstance(base, _SEEKABLE_SOURCES)


def _check_members(layer_tf: tarfile.TarFile, compressed_size: int) -> None:
    """Walk member headers once, stopping at the member-count or size bound."""
    max_members = _max_layer_members()
    max_bytes = _max_layer_uncompressed_bytes()
    count = 0
    total = 0
    while (member := layer_tf.next()) is not None:
        count += 1
        if count > max_members:
            raise LayerLimitError(
                "oci_layer_member_limit",
                "Container layer has more files than the member-count safety limit; image inventory is incomplete.",
            )
        if member.isfile():
            total += max(0, int(member.size))
            if total > max_bytes:
                raise LayerLimitError("oci_layer_size_limit", _LIMIT_DETAILS["oci_layer_size_limit"])
    if _decompression_ratio_exceeded(total, compressed_size):
        raise LayerLimitError("oci_layer_decompression_limit", _LIMIT_DETAILS["oci_layer_decompression_limit"])


@contextmanager
def open_bounded_layer(
    source: IO[bytes],
    compressed_size: int,
    budget: ScanBudget,
    *,
    outer: object | None = None,
) -> Iterator[tarfile.TarFile]:
    """Open one layer as an uncompressed, seekable tar without buffering it in RAM.

    ``outer`` is the file object of an enclosing archive (``docker save``);
    when that is compressed, seeking inside the layer would re-inflate the
    outer stream, so the layer is spooled instead of read in place.
    """
    budget.check()
    spool: IO[bytes] | None = None
    if not _is_compressed(_sniff(source)) and _is_cheaply_seekable(source, outer):
        layer_source: IO[bytes] = source
    else:
        spool = spool_layer(source, compressed_size, budget)
        layer_source = spool
    try:
        with tarfile.open(fileobj=layer_source, mode="r:") as layer_tf:
            _check_members(layer_tf, compressed_size)
            yield layer_tf
    finally:
        if spool is not None:
            spool.close()
