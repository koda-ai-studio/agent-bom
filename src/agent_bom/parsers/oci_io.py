"""Bounded archive reads and tar member safety for OCI images."""

from __future__ import annotations

import json
import logging
import posixpath
import tarfile
import zipfile
from pathlib import Path
from typing import IO

from agent_bom.core.settings import env_int
from agent_bom.parsers.oci_metadata import _MAX_LEGACY_RPMDB_BYTES as _MAX_LEGACY_RPMDB_BYTES
from agent_bom.parsers.oci_metadata import _parse_legacy_rpmdb_bytes as _parse_legacy_rpmdb_bytes
from agent_bom.parsers.oci_types import OCIParseError

_logger = logging.getLogger("agent_bom.oci_parser")


_MAX_JSON_MEMBER_BYTES = 100 * 1024 * 1024


_MAX_LAYER_UNCOMPRESSED_BYTES = 5 * 1024 * 1024 * 1024


_MAX_JAR_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


_MAX_DECOMPRESSION_RATIO = 100


def _env_int(name: str, default: int) -> int:
    value = env_int(name, None, on_invalid="default")
    return default if value is None else max(1, value)


def _max_json_member_bytes() -> int:
    return _env_int("AGENT_BOM_MAX_MANIFEST_BYTES", _MAX_JSON_MEMBER_BYTES)


def _max_layer_uncompressed_bytes() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES", _MAX_LAYER_UNCOMPRESSED_BYTES)


def _max_jar_uncompressed_bytes() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_JAR_UNCOMPRESSED_BYTES", _MAX_JAR_UNCOMPRESSED_BYTES)


def _max_decompression_ratio() -> int:
    return _env_int("AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO", _MAX_DECOMPRESSION_RATIO)


def _decompression_ratio_exceeded(uncompressed_bytes: int, compressed_bytes: int) -> bool:
    if compressed_bytes <= 0 or uncompressed_bytes <= 0:
        return False
    return uncompressed_bytes > compressed_bytes * _max_decompression_ratio()


def _is_safe_tar_member_name(name: str) -> bool:
    """Return True iff ``name`` is safe to treat as a relative path inside a tar.

    Rejects absolute paths, parent-traversal (``../``), NUL-injected names,
    and any name whose POSIX-normalized form escapes the tar root.
    """
    if not name or "\x00" in name:
        return False
    if name.startswith("/"):
        return False
    # posixpath.normpath collapses "./foo/../bar" → "bar" but preserves a
    # leading ".." if the name escapes. "a/../b" → "b" (safe);
    # "../a" → "../a" (escapes); "a/../../b" → "../b" (escapes).
    normalized = posixpath.normpath(name)
    if normalized.startswith("../") or normalized == "..":
        return False
    if normalized.startswith("/"):
        return False
    # Belt-and-suspenders against split-by-"/" bypasses on odd separators.
    parts = normalized.split("/")
    if any(p == ".." for p in parts):
        return False
    return True


def _safe_tar_names(tf: tarfile.TarFile) -> set[str]:
    """Return member names that are safe regular files inside ``tf``.

    Filters out:
      - names failing ``_is_safe_tar_member_name`` (traversal / absolute / NUL)
      - symlink members (``SYMTYPE``) and hardlink members (``LNKTYPE``)
      - device / fifo members

    Directory members are excluded because this helper exists to feed
    file-reading loops; directories carry no file payload.
    """
    safe: set[str] = set()
    rejected_traversal = 0
    rejected_link = 0
    for member in tf.getmembers():
        name = member.name
        if not _is_safe_tar_member_name(name):
            rejected_traversal += 1
            continue
        if member.issym() or member.islnk():
            # Symlinks / hardlinks inside an image layer are legitimate OS
            # artifacts — but we never follow them for package parsing. We
            # only ingest concrete regular-file payloads.
            rejected_link += 1
            continue
        if not member.isfile():
            # Skip directories, devices, fifos, etc.
            continue
        safe.add(name)
    if rejected_traversal:
        _logger.debug(
            "Rejected %d tar member(s) with unsafe names (traversal / absolute / NUL)",
            rejected_traversal,
        )
    if rejected_link:
        _logger.debug(
            "Skipped %d symlink/hardlink member(s) — package parsing reads concrete files only",
            rejected_link,
        )
    return safe


def _safe_getmember(tf: tarfile.TarFile, name: str) -> tarfile.TarInfo | None:
    """Resolve ``name`` to a tar member only if the name is safe AND the member is a regular file.

    Returns ``None`` (instead of raising ``KeyError``) so callers can treat a
    missing-or-unsafe member the same way they treat a missing-but-legitimate
    member: skip and move on.
    """
    if not _is_safe_tar_member_name(name):
        return None
    try:
        member = tf.getmember(name)
    except KeyError:
        return None
    if member.issym() or member.islnk() or not member.isfile():
        return None
    return member


def _safe_extractfile(tf: tarfile.TarFile, name: str) -> IO[bytes] | None:
    """Open a tar member by name, but only if it is safe (see ``_safe_getmember``).

    Returns ``None`` if the member is missing, a symlink / hardlink, has an
    unsafe name, or can't be opened as a stream. Callers can treat ``None``
    uniformly as "skip this member" without distinguishing the cause.
    """
    member = _safe_getmember(tf, name)
    if member is None:
        return None
    try:
        return tf.extractfile(member)
    except (tarfile.TarError, OSError) as e:
        _logger.debug("Failed to open tar member %s: %s: %s", name, type(e).__name__, e)
        return None


def _resolve_tar_member(tf: tarfile.TarFile, member_path: str) -> tarfile.TarInfo | None:
    """Resolve a tar member path with common Docker/OCI prefixes."""
    normalized = member_path.lstrip("./")
    for candidate in (member_path, normalized, f"./{normalized}"):
        try:
            return tf.getmember(candidate)
        except KeyError:
            continue
    return None


def _read_json_member_from_tar(tf: tarfile.TarFile, member_path: str) -> dict | None:
    """Read and decode a JSON file from an outer tarball when present."""
    member = _resolve_tar_member(tf, member_path)
    if member is None:
        return None
    if member.size > _max_json_member_bytes():
        _logger.debug("Skipping oversized JSON member %s", member_path)
        return None
    fileobj = tf.extractfile(member)
    if fileobj is None:
        return None
    try:
        data = fileobj.read(_max_json_member_bytes() + 1)
        if len(data) > _max_json_member_bytes():
            return None
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _read_json_path_limited(path: Path) -> dict | list | None:
    try:
        if path.stat().st_size > _max_json_member_bytes():
            _logger.debug("Skipping oversized JSON file: %s", path)
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _tar_uncompressed_regular_size(tf: tarfile.TarFile) -> int:
    total = 0
    for member in tf.getmembers():
        if member.isfile() and _is_safe_tar_member_name(member.name):
            total += max(0, int(member.size))
            if total > _max_layer_uncompressed_bytes():
                break
    return total


def _zip_uncompressed_size(zf: zipfile.ZipFile) -> int:
    total = 0
    for info in zf.infolist():
        total += max(0, int(info.file_size))
        if total > _max_jar_uncompressed_bytes():
            break
    return total


def _zip_compressed_size(zf: zipfile.ZipFile) -> int:
    total = 0
    for info in zf.infolist():
        total += max(0, int(info.compress_size))
    return total


def _query_legacy_rpmdb(layer_tf: tarfile.TarFile, database_path: str) -> list[tuple[str, str]]:
    """Read and decode one bounded BerkeleyDB/NDB package database member."""
    member = _safe_getmember(layer_tf, database_path)
    if member is None or not member.isfile() or member.size > _MAX_LEGACY_RPMDB_BYTES:
        raise OCIParseError("Legacy RPM database is missing, invalid, or exceeds the 512 MiB safety limit")
    source = _safe_extractfile(layer_tf, database_path)
    if source is None:
        raise OCIParseError("Legacy RPM database could not be read safely")
    packages = _parse_legacy_rpmdb_bytes(source.read())
    if not packages:
        raise OCIParseError("Legacy RPM database contains no valid package header records")
    return packages
