"""Go binaries built by Go 1.17 and older: the build info holds pointers, not strings.

Go 1.17 and older write a 32-byte header whose flags byte lacks the inline bit and
whose two words are virtual addresses of ``runtime.buildVersion`` and
``runtime.modinfo`` (see Go's ``src/debug/buildinfo/buildinfo.go``). The
version and module lines usually sit before the header in the file, so a scan
that only looked after the header found nothing and the image reported zero
packages as a clean result.
"""

from __future__ import annotations

import io
import struct

import pytest

from agent_bom.oci_parser import parse_oci_tarball
from agent_bom.parsers.go_buildinfo import read_go_buildinfo
from tests.test_oci_parser import _make_docker_save_tar

MAGIC = b"\xff Go buildinf:"
INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
INFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
MODINFO = (
    INFO_START
    + b"path\tgithub.com/prometheus/node_exporter\n"
    + b"mod\tgithub.com/prometheus/node_exporter\t(devel)\t\n"
    + b"dep\tgithub.com/prometheus/client_golang\tv1.11.0\th1:abc=\n"
    + b"dep\tgolang.org/x/sys\tv0.0.0-20211025201205-69cdffdb9359\th1:def=\n"
    + INFO_END
)

VERSION_OFF, MODINFO_OFF, HDRS_OFF, BUILDINFO_OFF, END = 0x200, 0x240, 0x400, 0x500, 0x600


def _payload(base: int, ptr_size: int, big_endian: bool, version: bytes = b"go1.17.3") -> bytearray:
    """The data a pre-1.18 linker lays out: strings, their headers, then the build info header."""
    order = ">" if big_endian else "<"
    word = "I" if ptr_size == 4 else "Q"
    body = bytearray(END)
    body[VERSION_OFF : VERSION_OFF + len(version)] = version
    body[MODINFO_OFF : MODINFO_OFF + len(MODINFO)] = MODINFO
    struct.pack_into(f"{order}{word}{word}", body, HDRS_OFF, base + VERSION_OFF, len(version))
    struct.pack_into(f"{order}{word}{word}", body, HDRS_OFF + 2 * ptr_size, base + MODINFO_OFF, len(MODINFO))
    header = MAGIC + bytes([ptr_size, 1 if big_endian else 0])
    header += struct.pack(f"{order}{word}{word}", base + HDRS_OFF, base + HDRS_OFF + 2 * ptr_size)
    body[BUILDINFO_OFF : BUILDINFO_OFF + len(header)] = header
    return body


def _elf(ptr_size: int = 8, big_endian: bool = False, version: bytes = b"go1.17.3") -> bytes:
    base = 0x400000
    body = _payload(base, ptr_size, big_endian, version)
    order = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes([2 if ptr_size == 8 else 1, 2 if big_endian else 1, 1]) + b"\x00" * 9
    if ptr_size == 8:
        ehdr = ident + struct.pack(f"{order}HHIQQQIHHHHHH", 2, 62, 1, base, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        phdr = struct.pack(f"{order}IIQQQQQQ", 1, 4, 0, base, base, END, END, 0x1000)
    else:
        ehdr = ident + struct.pack(f"{order}HHIIIIIHHHHHH", 2, 3, 1, base, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        phdr = struct.pack(f"{order}IIIIIIII", 1, 0, base, base, END, END, 4, 0x1000)
    head = ehdr + phdr
    body[: len(head)] = head
    return bytes(body)


def _macho64() -> bytes:
    base = 0x100000000
    body = _payload(base, 8, False)
    pagezero = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__PAGEZERO", 0, base, 0, 0, 0, 0, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__DATA", base, END, 0, END, 3, 3, 0, 0)
    head = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 2, 144, 0, 0) + pagezero + segment
    body[: len(head)] = head
    return bytes(body)


def _pe32plus() -> bytes:
    image_base, rva, raw = 0x400000, 0x1000, 0x100
    # The section maps file offset 0x100 at image_base + 0x1000, so payload addresses
    # use base = image_base + rva - raw.
    body = _payload(image_base + rva - raw, 8, False)
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 112, 0x22)
    optional = struct.pack("<HBBIIIII", 0x20B, 0, 0, 0, 0, 0, 0, 0) + struct.pack("<Q", image_base)
    optional += b"\x00" * (112 - len(optional))
    section = struct.pack("<8sIIIIIIHHI", b".data", END - raw, rva, END - raw, raw, 0, 0, 0, 0, 0xC0000040)
    head = dos + coff + optional + section
    assert len(head) <= raw
    body[: len(head)] = head
    return bytes(body)


def _window(binary: bytes) -> bytes:
    return binary[binary.index(MAGIC) :]


@pytest.mark.parametrize(
    "binary",
    [_elf(8, False), _elf(4, True), _macho64(), _pe32plus()],
    ids=["elf64-le", "elf32-be", "macho64", "pe32plus"],
)
def test_pointer_layout_resolves_version_and_modules(binary: bytes) -> None:
    info = read_go_buildinfo(io.BytesIO(binary), _window(binary))
    assert info.toolchain == "1.17.3"
    assert b"dep\tgithub.com/prometheus/client_golang\tv1.11.0" in info.modinfo
    assert not info.modinfo.startswith(INFO_START)


def test_unmappable_pointers_fall_back_to_searching_the_binary() -> None:
    binary = bytearray(_elf())
    # Corrupt the program header's virtual address so no pointer maps to the file.
    struct.pack_into("<Q", binary, 64 + 16, 0x900000)
    info = read_go_buildinfo(io.BytesIO(bytes(binary)), _window(bytes(binary)))
    assert info.toolchain == "1.17.3"
    assert b"dep\tgolang.org/x/sys\tv0.0.0-20211025201205-69cdffdb9359" in info.modinfo


def test_fallback_does_not_guess_between_two_go_releases() -> None:
    binary = bytearray(_elf())
    struct.pack_into("<Q", binary, 64 + 16, 0x900000)
    binary[0x300:0x30A] = b"\x00go1.13\x00\x00\x00"
    info = read_go_buildinfo(io.BytesIO(bytes(binary)), _window(bytes(binary)))
    assert info.toolchain is None
    assert b"dep\tgithub.com/prometheus/client_golang" in info.modinfo


def _scan(path: str, binary: bytes):
    return parse_oci_tarball(_make_docker_save_tar([{path: binary}]))


def test_go_117_binary_in_an_image_reports_stdlib_and_modules() -> None:
    result = _scan("bin/node_exporter", _elf())
    found = {(p.name, p.version, p.ecosystem) for p in result.packages}
    assert ("stdlib", "1.17.3", "go") in found
    assert ("github.com/prometheus/client_golang", "v1.11.0", "go") in found
    assert ("golang.org/x/sys", "v0.0.0-20211025201205-69cdffdb9359", "go") in found
    assert [w for w in result.coverage_warnings if w.path.endswith("node_exporter")] == []


def test_go_binary_with_no_readable_build_info_is_a_coverage_gap() -> None:
    binary = bytearray(END)
    binary[:4] = b"\x7fELF"
    binary[BUILDINFO_OFF : BUILDINFO_OFF + 32] = MAGIC + b"\x08\x00" + b"\xee" * 16
    result = _scan("bin/mystery", bytes(binary))
    assert result.packages == []
    assert [(w.path, w.reason) for w in result.coverage_warnings] == [("bin/mystery", "package_metadata_parse_error")]


def test_go_binary_with_modules_but_no_release_is_a_coverage_gap() -> None:
    result = _scan("bin/node_exporter", _elf(version=b"devel +abc"))
    names = {p.name for p in result.packages}
    assert "github.com/prometheus/client_golang" in names and "stdlib" not in names
    assert [w.path for w in result.coverage_warnings] == ["bin/node_exporter"]


def test_non_go_executable_is_not_a_gap() -> None:
    result = _scan("bin/tool", b"\x7fELF" + b"\x00" * 600)
    assert result.packages == []
    assert result.coverage_warnings == []
