"""Parsers oci metadata helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import IO, Optional

from agent_bom.security import sanitize_text

_MAX_LEGACY_RPMDB_BYTES = 512 * 1024 * 1024

# RPM header magic (8 bytes)
_RPM_HDR_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"

_RPMTAG_NAME = 1000

_RPMTAG_VERSION = 1001

_RPMTAG_RELEASE = 1002

_RPMTAG_EPOCH = 1003

_RPM_TYPE_INT32 = 4

_RPM_TYPE_STRING = 6


def is_node_package_manifest_path(member_path: str) -> bool:
    """Return whether a path is an npm package-root manifest.

    Packages may contain subpath ``package.json`` files for export conditions
    (for example ``nanoid/non-secure/package.json``).  Those are not inventory
    candidates and a missing name/version there is not incomplete coverage.
    """
    normalized = member_path.replace("\\", "/")
    marker = "/node_modules/"
    if marker not in normalized or not normalized.endswith("/package.json"):
        return False
    if normalized.count(marker) != 1:
        return False
    relative = normalized.split(marker, 1)[1].split("/")
    if len(relative) == 2:
        return not relative[0].startswith("@") and relative[1] == "package.json"
    return len(relative) == 3 and relative[0].startswith("@") and relative[2] == "package.json"


@dataclass(frozen=True)
class LayerMetadata:
    """Build and filesystem provenance for a concrete image layer."""

    layer_index: int
    layer_id: str
    layer_path: str
    created_by: Optional[str] = None
    dockerfile_instruction: Optional[str] = None


def _normalize_layer_id(layer_path: str) -> str:
    """Return a stable layer identifier from a tar/layout path."""
    layer_path = layer_path.lstrip("./")
    if layer_path.startswith("blobs/sha256/"):
        return f"sha256:{layer_path.rsplit('/', 1)[-1]}"
    if layer_path.endswith("/layer.tar"):
        return layer_path[: -len("/layer.tar")]
    return layer_path


def _normalize_dockerfile_instruction(created_by: Optional[str]) -> Optional[str]:
    """Convert raw OCI history ``created_by`` text into a Dockerfile-like instruction."""
    if not created_by:
        return None

    raw = created_by.strip()
    for prefix in ("/bin/sh -c #(nop) ", "cmd /S /C #(nop) "):
        if raw.startswith(prefix):
            return raw[len(prefix) :].strip() or raw

    for prefix in ("/bin/sh -c ", "cmd /S /C "):
        if raw.startswith(prefix):
            command = raw[len(prefix) :].strip()
            return f"RUN {command}" if command else "RUN"

    return raw


def _build_layer_metadata(layer_paths: list[str], config: dict | None = None) -> list[LayerMetadata]:
    """Map image layers to normalized build-step metadata."""
    histories = (config or {}).get("history", [])
    metadata: list[LayerMetadata] = []
    history_cursor = 0

    for index, layer_path in enumerate(layer_paths, start=1):
        created_by: str | None = None
        dockerfile_instruction: str | None = None

        while history_cursor < len(histories):
            entry = histories[history_cursor]
            history_cursor += 1
            if entry.get("empty_layer"):
                continue
            raw_created_by = entry.get("created_by")
            # Build args and ENV values land in history verbatim; keep the step, redact the secret.
            created_by = sanitize_text(raw_created_by, max_len=4000) if isinstance(raw_created_by, str) and raw_created_by else None
            dockerfile_instruction = _normalize_dockerfile_instruction(created_by)
            break

        metadata.append(
            LayerMetadata(
                layer_index=index,
                layer_id=_normalize_layer_id(layer_path),
                layer_path=layer_path,
                created_by=created_by,
                dockerfile_instruction=dockerfile_instruction,
            )
        )

    return metadata


# ─── RPM header parser ────────────────────────────────────────────────────────


def _parse_rpm_header_blob(blob: bytes) -> Optional[tuple[str, str]]:
    """Parse a minimal RPM header blob and return (name, version) or None.

    RPM header layout (big-endian):
    - 8 bytes magic  -- PRESENT on legacy BerkeleyDB/NDB records, ABSENT in the
      ``rpmdb.sqlite`` ``Packages.blob`` column
    - 4 bytes nindex (number of tag entries)
    - 4 bytes hsize (size of data section)
    - nindex × 16-byte entries: tag(4) type(4) offset(4) count(4)
    - data section (hsize bytes)

    Both framings are accepted. Requiring the magic meant every blob from a
    ``rpmdb.sqlite`` returned None, so RHEL 9+, UBI9, Fedora 33+, Amazon Linux
    2023 and Rocky 9 images -- everything on RPM >= 4.16, which is the default
    backend -- reported **zero** OS packages and therefore zero OS CVEs. A
    scanner that finds nothing on the most common enterprise base image is the
    "reports less than it found" failure, and it looks clean.
    """
    if len(blob) < 16:
        return None
    try:
        if blob[:8] == _RPM_HDR_MAGIC:
            nindex = struct.unpack_from(">I", blob, 8)[0]
            index_start = 16
        else:
            # sqlite framing: the record begins at nindex directly.
            nindex = struct.unpack_from(">I", blob, 0)[0]
            index_start = 8
        # A wild nindex means this is not a header at all; bound it before it
        # becomes a multi-gigabyte slice.
        if nindex == 0 or nindex > 100_000:
            return None
        data_start = index_start + nindex * 16

        if data_start > len(blob):
            return None

        tags: dict[int, tuple[int, int]] = {}  # tag → (type, offset)
        for i in range(nindex):
            pos = index_start + i * 16
            tag = struct.unpack_from(">I", blob, pos)[0]
            type_ = struct.unpack_from(">I", blob, pos + 4)[0]
            offset = struct.unpack_from(">I", blob, pos + 8)[0]
            tags[tag] = (type_, offset)

        name = _rpm_read_str(blob, tags, data_start, _RPMTAG_NAME)
        version = _rpm_read_str(blob, tags, data_start, _RPMTAG_VERSION)
        release = _rpm_read_str(blob, tags, data_start, _RPMTAG_RELEASE)
        epoch = _rpm_read_int32(blob, tags, data_start, _RPMTAG_EPOCH)
        if not name or not version:
            return None
        full_version = f"{version}-{release}" if release else version
        if epoch:
            full_version = f"{epoch}:{full_version}"
        return name, full_version
    except (struct.error, OverflowError):
        return None


def _parse_legacy_rpmdb_bytes(database: bytes) -> list[tuple[str, str]]:
    """Extract embedded RPM header records from BerkeleyDB or NDB payloads.

    Both legacy backends store canonical RPM header blobs as record values. The
    database page/index format is backend-specific, but the value format is not:
    every package header starts with ``_RPM_HDR_MAGIC`` and carries bounded index
    and data lengths. Scanning for those self-describing records avoids a native
    BerkeleyDB dependency while preserving exact RPM name/version/release data.
    """
    packages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    cursor = 0
    while True:
        start = database.find(_RPM_HDR_MAGIC, cursor)
        if start < 0:
            break
        cursor = start + len(_RPM_HDR_MAGIC)
        if start + 16 > len(database):
            continue
        try:
            nindex, hsize = struct.unpack_from(">II", database, start + 8)
        except struct.error:
            continue
        if nindex > 100_000 or hsize > _MAX_LEGACY_RPMDB_BYTES:
            continue
        record_size = 16 + nindex * 16 + hsize
        end = start + record_size
        if record_size < 16 or end > len(database):
            continue
        parsed = _parse_rpm_header_blob(database[start:end])
        if parsed is None or parsed[0] == "gpg-pubkey" or parsed in seen:
            continue
        seen.add(parsed)
        packages.append(parsed)
        cursor = end
    return packages


def _parse_rfc822_name_version(fileobj: IO[bytes]) -> tuple[str, str]:
    """Extract ``Name``/``Version`` from an RFC822 Python metadata stream.

    Shared by the modern ``*.dist-info/METADATA`` and the legacy
    ``*.egg-info/PKG-INFO`` (or ``*.egg-info/METADATA``) parsers — both use the
    same header format, only the file location differs.
    """
    pkg_name = pkg_version = ""
    for raw_line in fileobj:
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if line.startswith("Name:"):
            pkg_name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            pkg_version = line.split(":", 1)[1].strip()
        if pkg_name and pkg_version:
            break
    return pkg_name, pkg_version


def _rpm_read_str(blob: bytes, tags: dict[int, tuple[int, int]], data_start: int, tag_id: int) -> str:
    if tag_id not in tags:
        return ""
    type_, offset = tags[tag_id]
    if type_ != _RPM_TYPE_STRING:
        return ""
    abs_pos = data_start + offset
    end = blob.find(b"\x00", abs_pos)
    if end == -1:
        return ""
    return blob[abs_pos:end].decode("utf-8", errors="ignore")


def _rpm_read_int32(blob: bytes, tags: dict[int, tuple[int, int]], data_start: int, tag_id: int) -> int:
    if tag_id not in tags:
        return 0
    type_, offset = tags[tag_id]
    abs_pos = data_start + offset
    if type_ != _RPM_TYPE_INT32 or abs_pos < data_start or abs_pos + 4 > len(blob):
        return 0
    return struct.unpack_from(">I", blob, abs_pos)[0]
