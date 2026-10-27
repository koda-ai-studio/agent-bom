"""Resource ceilings for untrusted serverless deployment archives."""

from __future__ import annotations

import io
import zipfile

from typing_extensions import Buffer

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EXPANSION_RATIO = 100


class ArchiveLimitError(ValueError):
    """Archive evidence was refused; callers must report incomplete coverage."""


class BoundedArchiveBuffer(io.BytesIO):
    """A sink for SDK downloads which refuses bytes before retaining them."""

    def write(self, data: Buffer, /) -> int:
        if self.tell() + memoryview(data).nbytes > MAX_ARCHIVE_BYTES:
            raise ArchiveLimitError("Deployment archive exceeds compressed byte limit")
        return super().write(data)


def validate_archive(zf: zipfile.ZipFile) -> None:
    """Reject all metadata budgets before decompressing any member."""
    members = zf.infolist()
    if len(members) > MAX_MEMBERS:
        raise ArchiveLimitError("Deployment archive exceeds member count limit")
    total = 0
    for member in members:
        if member.file_size > MAX_MEMBER_BYTES:
            raise ArchiveLimitError("Deployment archive exceeds per-member byte limit")
        total += member.file_size
        if total > MAX_TOTAL_BYTES:
            raise ArchiveLimitError("Deployment archive exceeds total uncompressed byte limit")
        if member.file_size > MAX_EXPANSION_RATIO * max(1, member.compress_size):
            raise ArchiveLimitError("Deployment archive exceeds expansion ratio limit")
        if member.flag_bits & 1:
            raise ArchiveLimitError("Encrypted deployment archive member cannot be inspected")


def read_member(zf: zipfile.ZipFile, member: zipfile.ZipInfo) -> bytes:
    """Bound the actual read as well as the declared ZIP size."""
    with zf.open(member) as stream:
        data = stream.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise ArchiveLimitError("Deployment archive exceeds per-member byte limit")
    return data
