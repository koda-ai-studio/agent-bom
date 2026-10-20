"""Package ecosystem extraction stages for OCI layers."""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Iterable, Iterator
from typing import IO

from agent_bom.package_utils import parse_debian_source_name
from agent_bom.parsers.cpython_runtime import _python_metadata_kind, extract_cpython_runtime
from agent_bom.parsers.oci_io import (
    _decompression_ratio_exceeded,
    _logger,
    _max_jar_uncompressed_bytes,
    _query_legacy_rpmdb,
    _safe_extractfile,
    _safe_getmember,
    _zip_compressed_size,
    _zip_uncompressed_size,
)
from agent_bom.parsers.oci_layer import _LayerScan
from agent_bom.parsers.oci_metadata import _parse_rfc822_name_version as _parse_rfc822_name_version
from agent_bom.parsers.oci_metadata import _parse_rpm_header_blob as _parse_rpm_header_blob
from agent_bom.parsers.oci_metadata import is_node_package_manifest_path as is_node_package_manifest_path
from agent_bom.parsers.oci_types import (
    _GEMSPEC_NAME_RE,
    _GEMSPEC_PATH_RE,
    _GEMSPEC_VER_RE,
    _GO_BIN_DIR_RE,
    _GO_BIN_MAX_READ,
    _GO_BUILDINFO_MAGIC,
    _GO_DEP_LINE_RE,
    _JAR_DIR_HINTS,
    _JAR_EXT_RE,
    _JAR_MAX_BYTES,
    _RPM_BDB_PATHS,
    _RPM_MANIFEST_PATHS,
    _RPM_MANIFEST_RE,
    _RPM_NDB_PATHS,
    _RPM_SQLITE_PATHS,
    _append_oci_warning,
)


def _parse_members(scan: _LayerScan, paths: Iterable[str], parse: Callable[[_LayerScan, str], None], failure: str) -> None:
    for path in paths:
        if scan.is_deleted(path):
            continue
        try:
            parse(scan, path)
        except Exception:
            _logger.debug(failure, path)
            scan.gap(path)


def _present_candidates(scan: _LayerScan, bases: tuple[str, ...]) -> Iterator[str]:
    for base in bases:
        for prefix in ("", "./"):
            if prefix + base in scan.names:
                yield prefix + base


def _extract_python_metadata(scan: _LayerScan) -> None:
    extract_cpython_runtime(scan, _safe_extractfile)
    # Older base images (e.g. Debian buster) ship pip/setuptools/wheel as
    # ``*.egg-info/PKG-INFO`` rather than ``*.dist-info/METADATA``; both use the
    # same RFC822 headers and ``_add_package`` dedupes a package found via both.
    for member_name in scan.names:
        metadata_kind = _python_metadata_kind(member_name)
        if metadata_kind is None or scan.is_deleted(member_name):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, member_name)
            if f is None:
                scan.gap(member_name)
                continue
            pkg_name, pkg_version = _parse_rfc822_name_version(f)
            if pkg_name and pkg_version:
                scan.add(member_name, pkg_name, pkg_version, "pypi")
            else:
                scan.gap(member_name)
        except Exception:
            _logger.debug("Skipped Python %s metadata: %s", metadata_kind, member_name)
            scan.gap(member_name)


def _add_node_manifest(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    data = json.loads(f.read().decode("utf-8", errors="ignore"))
    pkg_name = data.get("name", "")
    pkg_version = data.get("version", "unknown")
    if pkg_name:
        scan.add(path, pkg_name, pkg_version, "npm")
    else:
        scan.gap(path)


def _extract_node_manifests(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if is_node_package_manifest_path(name))
    _parse_members(scan, paths, _add_node_manifest, "Skipped Node package.json: %s")


def _add_dpkg_entries(scan: _LayerScan, path: str, content: str) -> bool:
    parsed_package = False
    pkg_name = pkg_version = ""
    source_package: str | None = None
    for line in content.splitlines():
        if line.startswith("Package:"):
            pkg_name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            pkg_version = line.split(":", 1)[1].strip()
        elif line.startswith("Source:"):
            source_package = parse_debian_source_name(line.split(":", 1)[1].strip())
        elif line == "" and pkg_name and pkg_version:
            scan.add(path, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}", source_package=source_package)
            parsed_package = True
            pkg_name = pkg_version = ""
            source_package = None
    if pkg_name and pkg_version:
        scan.add(path, pkg_name, pkg_version, "deb", f"pkg:deb/debian/{pkg_name}@{pkg_version}", source_package=source_package)
        parsed_package = True
    return parsed_package


def _add_apk_entries(scan: _LayerScan, path: str, content: str) -> bool:
    parsed_package = False
    pkg_name = pkg_version = ""
    source_package: str | None = None
    for line in content.splitlines():
        if line.startswith("P:"):
            pkg_name = line[2:].strip()
        elif line.startswith("V:"):
            pkg_version = line[2:].strip()
        elif line.startswith("o:") or line.startswith("O:"):
            source_package = line[2:].strip() or None
        elif line == "" and pkg_name and pkg_version:
            scan.add(path, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}", source_package=source_package)
            parsed_package = True
            pkg_name = pkg_version = ""
            source_package = None
    if pkg_name and pkg_version:
        scan.add(path, pkg_name, pkg_version, "apk", f"pkg:apk/alpine/{pkg_name}@{pkg_version}", source_package=source_package)
        parsed_package = True
    return parsed_package


def _extract_stanza_database(
    scan: _LayerScan, paths: tuple[str, ...], add_entries: Callable[[_LayerScan, str, str], bool], failure: str
) -> None:
    """Parse the first live copy of a blank-line separated package database."""
    for path in paths:
        if not scan.present(path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, path)
            if f:
                content = f.read().decode("utf-8", errors="ignore")
                if not add_entries(scan, path, content) and content.strip():
                    scan.gap(path)
            else:
                scan.gap(path)
        except Exception:
            _logger.debug(failure)
            scan.gap(path)
        break


def _extract_dpkg_status(scan: _LayerScan) -> None:
    _extract_stanza_database(scan, ("var/lib/dpkg/status", "./var/lib/dpkg/status"), _add_dpkg_entries, "Failed to parse dpkg status")


def _extract_apk_installed(scan: _LayerScan) -> None:
    _extract_stanza_database(scan, ("lib/apk/db/installed", "./lib/apk/db/installed"), _add_apk_entries, "Failed to parse Alpine apk db")


def _add_rpm(scan: _LayerScan, path: str, rpm_name: str, rpm_ver: str) -> None:
    scan.add(path, rpm_name, rpm_ver, "rpm", f"pkg:rpm/redhat/{rpm_name}@{rpm_ver}")


def _add_rpm_manifest_lines(scan: _LayerScan, path: str, fileobj: IO[bytes]) -> tuple[bool, bool]:
    had_content = parsed_package = False
    for raw_line in fileobj:
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        had_content = True
        match = _RPM_MANIFEST_RE.match(line.split()[0])
        if match is None:
            continue
        parsed_package = True
        if match.group("name") != "gpg-pubkey":
            _add_rpm(scan, path, match.group("name"), match.group("version"))
    return had_content, parsed_package


def _extract_rpm_manifest(scan: _LayerScan) -> None:
    for rpm_path in _RPM_MANIFEST_PATHS:
        if not scan.present(rpm_path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, rpm_path)
            if f:
                had_content, parsed_package = _add_rpm_manifest_lines(scan, rpm_path, f)
                if had_content and not parsed_package:
                    scan.gap(rpm_path)
            else:
                scan.gap(rpm_path)
        except Exception:
            _logger.debug("Failed to parse rpm manifest")
            scan.gap(rpm_path)
        break


def _add_rpm_sqlite_rows(scan: _LayerScan, path: str, db_bytes: bytes) -> None:
    # sqlite3 can only open a database from a real file.
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp.write(db_bytes)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(tmp_path)
        try:
            rows = conn.execute("SELECT blob FROM Packages").fetchall()
            parsed_package = False
            for (blob,) in rows:
                result = _parse_rpm_header_blob(blob) if isinstance(blob, bytes) else None
                if result:
                    parsed_package = True
                    if result[0] != "gpg-pubkey":
                        _add_rpm(scan, path, *result)
            if rows and not parsed_package:
                scan.gap(path)
        finally:
            conn.close()
    finally:
        os.unlink(tmp_path)


def _extract_rpm_sqlite(scan: _LayerScan) -> None:
    for sqlite_path in _RPM_SQLITE_PATHS:
        if not scan.present(sqlite_path):
            continue
        try:
            f = _safe_extractfile(scan.layer_tf, sqlite_path)
            if f is None:
                scan.gap(sqlite_path)
                continue
            _add_rpm_sqlite_rows(scan, sqlite_path, f.read())
        except Exception:
            _logger.debug("Failed to parse rpmdb.sqlite")
            scan.gap(sqlite_path)
        break


def _extract_legacy_rpmdb(scan: _LayerScan) -> None:
    if any(scan.present(p) for p in (*_RPM_SQLITE_PATHS, *_RPM_MANIFEST_PATHS)):
        return
    legacy_rpmdb = next((p for p in (*_RPM_BDB_PATHS, *_RPM_NDB_PATHS) if scan.present(p)), None)
    if legacy_rpmdb:
        for rpm_name, rpm_ver in _query_legacy_rpmdb(scan.layer_tf, legacy_rpmdb):
            _add_rpm(scan, legacy_rpmdb, rpm_name, rpm_ver)


def _sized_jar_member(scan: _LayerScan, member_name: str) -> tarfile.TarInfo | None:
    member = _safe_getmember(scan.layer_tf, member_name)
    if member is None or member.size == 0:
        scan.gap(member_name)
        return None
    if member.size > _JAR_MAX_BYTES:
        if scan.warnings is not None and scan.coverage_warnings is not None:
            _append_oci_warning(
                scan.warnings,
                scan.coverage_warnings,
                path=member_name,
                reason="package_metadata_size_limit",
                detail="Container package metadata exceeds the JAR safety limit; image inventory is incomplete.",
                message=f"JAR exceeds package metadata size limit: {member_name}",
            )
        return None
    return member


def _jar_within_limits(zf: zipfile.ZipFile, member_name: str) -> bool:
    jar_uncompressed_bytes = _zip_uncompressed_size(zf)
    if jar_uncompressed_bytes > _max_jar_uncompressed_bytes():
        _logger.debug("Skipping oversized JAR payload: %s", member_name)
        return False
    if _decompression_ratio_exceeded(jar_uncompressed_bytes, _zip_compressed_size(zf)):
        _logger.debug("Skipping high-ratio compressed JAR payload: %s", member_name)
        return False
    return True


def _read_jar_pairs(zf: zipfile.ZipFile, entry: str, separator: str, skip_comments: bool) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for line in zf.read(entry).decode("utf-8", errors="ignore").splitlines():
        if separator in line and not (skip_comments and line.startswith("#")):
            key, _, value = line.partition(separator)
            pairs[key.strip()] = value.strip()
    return pairs


def _add_jar_pom_properties(scan: _LayerScan, member_name: str, zf: zipfile.ZipFile, jar_names: list[str]) -> bool:
    found = False
    pom_props_paths = [n for n in jar_names if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n)]
    for prop_path in pom_props_paths:
        props = _read_jar_pairs(zf, prop_path, "=", skip_comments=True)
        artifact_id = props.get("artifactId", "")
        version = props.get("version", "")
        group_id = props.get("groupId", "")
        if artifact_id and version:
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}" if group_id else f"pkg:maven/{artifact_id}@{version}"
            scan.add(member_name, artifact_id, version, "maven", purl)
            found = True
    return found


def _add_jar_manifest(scan: _LayerScan, member_name: str, zf: zipfile.ZipFile) -> None:
    mf = _read_jar_pairs(zf, "META-INF/MANIFEST.MF", ": ", skip_comments=False)
    title = mf.get("Implementation-Title") or mf.get("Bundle-Name", "")
    version = mf.get("Implementation-Version") or mf.get("Bundle-Version", "")
    if title and version and not title.startswith("$") and not version.startswith("$"):
        scan.add(member_name, title, version, "maven")


def _add_jar_packages(scan: _LayerScan, member_name: str, member: tarfile.TarInfo) -> None:
    f = scan.layer_tf.extractfile(member)
    if f is None:
        scan.gap(member_name)
        return
    with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
        if not _jar_within_limits(zf, member_name):
            return
        jar_names = zf.namelist()
        # Prefer pom.properties coordinates; MANIFEST.MF is the fallback.
        found = _add_jar_pom_properties(scan, member_name, zf, jar_names)
        if not found and "META-INF/MANIFEST.MF" in jar_names:
            _add_jar_manifest(scan, member_name, zf)


def _extract_jars(scan: _LayerScan) -> None:
    for member_name in scan.names:
        if not _JAR_EXT_RE.search(member_name) or scan.is_deleted(member_name):
            continue
        # Tar paths may lack a leading '/'; prepend one for hint matching.
        name_for_hint = "/" + member_name.lower()
        if not any(hint in name_for_hint for hint in _JAR_DIR_HINTS):
            continue
        member = _sized_jar_member(scan, member_name)
        if member is None:
            continue
        try:
            _add_jar_packages(scan, member_name, member)
        except Exception:
            _logger.debug("Skipped JAR: %s", member_name)
            scan.gap(member_name)


def _add_go_buildinfo(scan: _LayerScan, member_name: str, member: tarfile.TarInfo) -> None:
    f = scan.layer_tf.extractfile(member)
    if f is None:
        return
    chunk = f.read(_GO_BIN_MAX_READ)
    if _GO_BUILDINFO_MAGIC not in chunk:
        return
    for m in _GO_DEP_LINE_RE.finditer(chunk):
        mod_path = m.group(1).decode("utf-8", errors="ignore").strip()
        mod_ver = m.group(2).decode("utf-8", errors="ignore").strip()
        if mod_path and mod_ver:
            scan.add(member_name, mod_path, mod_ver, "golang", f"pkg:golang/{mod_path}@{mod_ver}")


def _extract_go_binaries(scan: _LayerScan) -> None:
    for member_name in scan.names:
        if not _GO_BIN_DIR_RE.match(member_name) or scan.is_deleted(member_name):
            continue
        member = _safe_getmember(scan.layer_tf, member_name)
        if member is None or member.size < 64:
            continue
        try:
            _add_go_buildinfo(scan, member_name, member)
        except Exception:
            _logger.debug("Skipped Go binary: %s", member_name)


def _add_gemspec(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    content = f.read(32 * 1024).decode("utf-8", errors="ignore")
    name_m = _GEMSPEC_NAME_RE.search(content)
    ver_m = _GEMSPEC_VER_RE.search(content)
    if name_m and ver_m:
        scan.add(path, name_m.group(1), ver_m.group(1), "gem", f"pkg:gem/{name_m.group(1)}@{ver_m.group(1)}")
    else:
        scan.gap(path)


def _extract_gemspecs(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if _GEMSPEC_PATH_RE.search(name))
    _parse_members(scan, paths, _add_gemspec, "Skipped gemspec: %s")


def _add_deps_json(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    deps = json.loads(f.read().decode("utf-8", errors="ignore"))
    for lib_key, lib_val in deps.get("libraries", {}).items():
        # Library keys are "PackageName/1.2.3"; only type=package entries are NuGet packages.
        if lib_val.get("type") != "package" or "/" not in lib_key:
            continue
        pkg_name, _, pkg_ver = lib_key.rpartition("/")
        if pkg_name and pkg_ver:
            scan.add(path, pkg_name, pkg_ver, "nuget", f"pkg:nuget/{pkg_name}@{pkg_ver}")


def _extract_deps_json(scan: _LayerScan) -> None:
    paths = (name for name in scan.names if name.endswith(".deps.json"))
    _parse_members(scan, paths, _add_deps_json, "Skipped deps.json: %s")


def _add_composer_lock(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    data = json.loads(f.read().decode("utf-8", errors="ignore"))
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown").lstrip("v")
            if name:
                scan.add(path, name, version, "composer", f"pkg:composer/{name}@{version}")


def _extract_composer_locks(scan: _LayerScan) -> None:
    bases = ("app/composer.lock", "var/www/composer.lock", "var/www/html/composer.lock", "srv/composer.lock", "home/composer.lock")
    _parse_members(scan, _present_candidates(scan, bases), _add_composer_lock, "Failed to parse composer.lock: %s")


def _add_cargo_lock(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    content = f.read().decode("utf-8", errors="ignore")
    parsed_package = False
    for block in re.split(r"\[\[package\]\]", content):
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name_m and ver_m:
            scan.add(path, name_m.group(1), ver_m.group(1), "cargo", f"pkg:cargo/{name_m.group(1)}@{ver_m.group(1)}")
            parsed_package = True
    if "[[package]]" in content and not parsed_package:
        scan.gap(path)


def _extract_cargo_locks(scan: _LayerScan) -> None:
    bases = ("app/Cargo.lock", "usr/src/Cargo.lock", "home/Cargo.lock", "opt/Cargo.lock", "srv/Cargo.lock")
    _parse_members(scan, _present_candidates(scan, bases), _add_cargo_lock, "Failed to parse Cargo.lock: %s")


def _add_swift_resolved(scan: _LayerScan, path: str) -> None:
    f = _safe_extractfile(scan.layer_tf, path)
    if f is None:
        scan.gap(path)
        return
    data = json.loads(f.read().decode("utf-8", errors="ignore"))
    pins = data.get("pins", [])
    if not pins and "object" in data:
        pins = data["object"].get("pins", [])
    for pin in pins:
        identity = pin.get("identity", "")
        location = pin.get("location", pin.get("repositoryURL", ""))
        version = pin.get("state", {}).get("version") or "unknown"
        name = identity or (location.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") if location else "")
        if name:
            scan.add(path, name, version, "swift", f"pkg:swift/{name}@{version}")


def _extract_swift_resolved(scan: _LayerScan) -> None:
    bases = ("app/Package.resolved", "Package.resolved", "Sources/Package.resolved")
    _parse_members(scan, _present_candidates(scan, bases), _add_swift_resolved, "Failed to parse Package.resolved: %s")


_LAYER_PACKAGE_STAGES: tuple[Callable[[_LayerScan], None], ...] = (
    _extract_python_metadata,
    _extract_node_manifests,
    _extract_dpkg_status,
    _extract_apk_installed,
    _extract_rpm_manifest,
    _extract_rpm_sqlite,
    _extract_legacy_rpmdb,
    _extract_jars,
    _extract_go_binaries,
    _extract_gemspecs,
    _extract_deps_json,
    _extract_composer_locks,
    _extract_cargo_locks,
    _extract_swift_resolved,
)
