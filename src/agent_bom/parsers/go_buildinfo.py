"""Read the Go release that built a binary from its embedded build information."""

from __future__ import annotations

import re

from agent_bom.parsers.oci_types import _GO_BUILDINFO_MAGIC

_GO_TOOLCHAIN_RE = re.compile(rb"go(1)\.(\d{1,3})(?:\.(\d{1,3}))?(?:(rc|beta)(\d{1,3}))?(?=$|[\s+-])")
_GO_HEADER_LEN = 32
_GO_INLINE_STRINGS = 0x2


def go_toolchain_version(buildinfo: bytes) -> str | None:
    """The Go release that built a binary, as OSV ``stdlib`` semver (``1.18.2``, ``1.22.0-rc.1``).

    Go 1.18+ writes the version inline after the 32-byte build-info header as a
    varint-prefixed string. Older layouts hold pointers instead and a ``devel``
    toolchain has no release, so both return None rather than a guess.
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
    raw = buildinfo[offset : offset + min(length, 128)]
    match = _GO_TOOLCHAIN_RE.match(raw)
    if match is None:
        return None
    major, minor, patch, pre, pre_number = match.groups()
    version = f"{int(major)}.{int(minor)}.{int(patch or 0)}"
    return f"{version}-{pre.decode()}.{int(pre_number)}" if pre else version
