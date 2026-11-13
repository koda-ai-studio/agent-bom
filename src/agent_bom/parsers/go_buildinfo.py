"""Read the Go release and module list that built a binary from its embedded build information.

The layout follows Go's ``src/debug/buildinfo/buildinfo.go``: a 32-byte header
(magic, pointer size, flags). Go 1.18+ sets flag bit 0x2 and writes the version
and module info inline after the header as varint-prefixed strings. Go 1.13-1.17
leave that bit clear and store two virtual addresses of Go string headers
(``runtime.buildVersion`` and ``runtime.modinfo``), which are mapped to file
offsets through the ELF, Mach-O or PE segment table.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import IO

from agent_bom.parsers.oci_types import _GO_BIN_MAX_READ, _GO_BUILDINFO_MAGIC

_GO_TOOLCHAIN_RE = re.compile(rb"go(1)\.(\d{1,3})(?:\.(\d{1,3}))?(?:(rc|beta)(\d{1,3}))?(?=$|[\s+-])")
_GO_TOOLCHAIN_SCAN_RE = re.compile(rb"(?<![\w.])go1\.\d{1,3}(?:\.\d{1,3})?(?:(?:rc|beta)\d{1,3})?(?![\w.])")
_GO_HEADER_LEN = 32
_GO_INLINE_STRINGS = 0x2
_GO_VERSION_MAX = 128
# cmd/go/internal/modload infoStart / infoEnd: the framing around pre-1.18 modinfo.
_GO_MODINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
_GO_MODINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
_EXE_HEADER_READ = 64 * 1024
_MAX_SEGMENTS = 512
_SCAN_CHUNK = 1024 * 1024
_SCAN_OVERLAP = 64

_Segment = tuple[int, int, int]  # (virtual address, file size, file offset)


@dataclass(frozen=True)
class GoBuildInfo:
    """What a Go binary records about its build; ``toolchain`` is None for ``devel`` or unknown releases."""

    toolchain: str | None
    modinfo: bytes


def _normalize_toolchain(raw: bytes) -> str | None:
    match = _GO_TOOLCHAIN_RE.match(raw)
    if match is None:
        return None
    major, minor, patch, pre, pre_number = match.groups()
    version = f"{int(major)}.{int(minor)}.{int(patch or 0)}"
    return f"{version}-{pre.decode()}.{int(pre_number)}" if pre else version


def go_toolchain_version(buildinfo: bytes) -> str | None:
    """The Go release that built a binary, as OSV ``stdlib`` semver (``1.18.2``, ``1.22.0-rc.1``).

    Reads only the inline Go 1.18+ layout; a pointer layout needs the whole
    executable (see :func:`read_go_buildinfo`). A ``devel`` toolchain has no
    release and returns None rather than a guess.
    """
    if len(buildinfo) <= _GO_HEADER_LEN or not buildinfo[len(_GO_BUILDINFO_MAGIC) + 1] & _GO_INLINE_STRINGS:
        return None
    length, offset = 0, _GO_HEADER_LEN
    for shift in range(0, 35, 7):
        if offset >= len(buildinfo):
            return None
        byte = buildinfo[offset]
        offset += 1
        length |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
    return _normalize_toolchain(buildinfo[offset : offset + min(length, _GO_VERSION_MAX)])


def read_go_buildinfo(stream: IO[bytes], window: bytes) -> GoBuildInfo:
    """Decode the build info of a seekable Go executable whose header starts ``window``.

    When the pointer layout cannot be resolved, the whole binary is searched for
    the framed module info and a single unambiguous ``go1.x`` release string;
    without framed module info, dependency lines after the header still count.
    """
    if not window.startswith(_GO_BUILDINFO_MAGIC) or len(window) < _GO_HEADER_LEN:
        return GoBuildInfo(None, b"")
    if window[len(_GO_BUILDINFO_MAGIC) + 1] & _GO_INLINE_STRINGS:
        return GoBuildInfo(go_toolchain_version(window), window)
    decoded = _read_pointer_buildinfo(stream, window)
    return decoded if decoded is not None else _search_binary(stream, window)


def _read_pointer_buildinfo(stream: IO[bytes], window: bytes) -> GoBuildInfo | None:
    ptr_size = window[14]
    if ptr_size not in (4, 8):
        return None
    word = ("<", ">")[window[15] != 0] + ("I" if ptr_size == 4 else "Q")
    segments = _executable_segments(stream)
    if not segments:
        return None
    version_ptr, modinfo_ptr = struct.unpack_from(word + word[-1], window, 16)
    version = _read_go_string(stream, segments, word, ptr_size, version_ptr, _GO_VERSION_MAX)
    if not version:
        return None
    modinfo = _read_go_string(stream, segments, word, ptr_size, modinfo_ptr, _GO_BIN_MAX_READ) or b""
    if len(modinfo) >= 33 and modinfo[-17:-16] == b"\n":
        modinfo = modinfo[16:-16]
    else:
        modinfo = b""
    return GoBuildInfo(_normalize_toolchain(version), modinfo)


def _read_go_string(stream: IO[bytes], segments: list[_Segment], word: str, ptr_size: int, addr: int, limit: int) -> bytes | None:
    header = _read_at(stream, segments, addr, 2 * ptr_size)
    if header is None or len(header) < 2 * ptr_size:
        return None
    data_addr, data_len = struct.unpack(word + word[-1], header)
    if data_len > limit:
        return None
    data = _read_at(stream, segments, data_addr, data_len)
    return data if data is not None and len(data) == data_len else None


def _read_at(stream: IO[bytes], segments: list[_Segment], addr: int, size: int) -> bytes | None:
    for vaddr, filesz, offset in segments:
        if vaddr <= addr < vaddr + filesz:
            stream.seek(offset + addr - vaddr)
            return stream.read(min(size, vaddr + filesz - addr))
    return None


def _executable_segments(stream: IO[bytes]) -> list[_Segment]:
    stream.seek(0)
    head = stream.read(_EXE_HEADER_READ)
    try:
        if head.startswith(b"\x7fELF"):
            return _elf_segments(head)
        if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            return _macho_segments(head)
        if head.startswith(b"MZ"):
            return _pe_segments(head)
    except struct.error:
        return []
    return []


def _elf_segments(head: bytes) -> list[_Segment]:
    is64, order = head[4] == 2, ("<", ">")[head[5] == 2]
    if is64:
        phoff, phentsize, phnum = struct.unpack_from(order + "Q", head, 32)[0], *struct.unpack_from(order + "HH", head, 54)
        layout, fields = order + "IIQQQQ", (3, 5, 2)
    else:
        phoff, phentsize, phnum = struct.unpack_from(order + "I", head, 28)[0], *struct.unpack_from(order + "HH", head, 42)
        layout, fields = order + "IIIIII", (2, 4, 1)
    segments = []
    for index in range(min(phnum, _MAX_SEGMENTS)):
        values = struct.unpack_from(layout, head, phoff + index * phentsize)
        vaddr, filesz, offset = (values[i] for i in fields)
        if filesz:
            segments.append((vaddr, filesz, offset))
    return segments


def _macho_segments(head: bytes) -> list[_Segment]:
    order = "<" if head[0] in (0xCF, 0xCE) else ">"
    is64 = head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    ncmds = struct.unpack_from(order + "I", head, 16)[0]
    position, segments = 32 if is64 else 28, []
    for _ in range(min(ncmds, _MAX_SEGMENTS)):
        cmd, cmdsize = struct.unpack_from(order + "II", head, position)
        if cmdsize < 8:
            break
        if cmd in (0x19, 0x1):
            name = head[position + 8 : position + 24].rstrip(b"\x00")
            layout = order + ("QQQQ" if cmd == 0x19 else "IIII")
            vaddr, _vmsize, offset, filesz = struct.unpack_from(layout, head, position + 24)
            if filesz and name != b"__PAGEZERO":
                segments.append((vaddr, filesz, offset))
        position += cmdsize
    return segments


def _pe_segments(head: bytes) -> list[_Segment]:
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    if head[pe : pe + 4] != b"PE\x00\x00":
        return []
    nsections, optional_size = struct.unpack_from("<H", head, pe + 6)[0], struct.unpack_from("<H", head, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", head, optional)[0]
    image_base = struct.unpack_from("<Q", head, optional + 24)[0] if magic == 0x20B else struct.unpack_from("<I", head, optional + 28)[0]
    segments = []
    for index in range(min(nsections, _MAX_SEGMENTS)):
        _vsize, rva, raw_size, raw_offset = struct.unpack_from("<IIII", head, optional + optional_size + index * 40 + 8)
        if raw_size:
            segments.append((image_base + rva, raw_size, raw_offset))
    return segments


def _search_binary(stream: IO[bytes], window: bytes) -> GoBuildInfo:
    """Find framed module info and the release string anywhere in the binary, with bounded memory."""
    stream.seek(0)
    releases: set[bytes] = set()
    modinfo = b""
    tail = b""
    while chunk := stream.read(_SCAN_CHUNK):
        data = tail + chunk
        releases.update(_GO_TOOLCHAIN_SCAN_RE.findall(data))
        if not modinfo and (start := data.find(_GO_MODINFO_START)) >= 0:
            modinfo = _framed_modinfo(stream, data[start + len(_GO_MODINFO_START) :])
        tail = data[-_SCAN_OVERLAP:]
    toolchain = _normalize_toolchain(next(iter(releases))) if len(releases) == 1 else None
    return GoBuildInfo(toolchain, modinfo or window)


def _framed_modinfo(stream: IO[bytes], data: bytes) -> bytes:
    resume = stream.tell()
    while (end := data.find(_GO_MODINFO_END)) < 0 and len(data) < _GO_BIN_MAX_READ:
        more = stream.read(_SCAN_CHUNK)
        if not more:
            break
        data += more
    stream.seek(resume)
    return data[:end] if end >= 0 else b""
