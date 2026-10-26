"""Native OCI / Docker-save image layer parser — no external tools required.

Parses OCI image tarballs created by ``docker save <image> -o image.tar``
or OCI image layout directories (from skopeo/crane) and extracts packages
without requiring Grype, Syft, or Docker CLI.

Supported image formats:
- **Docker save tarball** — ``manifest.json`` + ``<hash>/layer.tar`` inside outer tar.
- **OCI image layout tarball** — ``index.json`` + ``blobs/sha256/<hash>`` inside outer tar.
- **OCI image layout directory** — same structure, unarchived (for skopeo/crane output).

Package ecosystems extracted from each layer filesystem:
- Python: ``*.dist-info/METADATA`` (modern wheels) and the legacy
  ``*.egg-info/PKG-INFO`` / ``*.egg-info/METADATA`` (setuptools/pip on older
  base images such as Debian buster ship pip/setuptools/wheel this way)
- Node: ``node_modules/*/package.json``
- Debian/Ubuntu: ``var/lib/dpkg/status``
- Alpine Linux: ``lib/apk/db/installed``
- RPM: modern SQLite plus legacy BerkeleyDB/NDB package databases and ``var/log/installed-rpms``
- Java: ``*.jar``/``*.war``/``*.ear`` → ``META-INF/maven/*/pom.properties`` or ``META-INF/MANIFEST.MF``
- Go binaries: embedded buildinfo (``ÿ Go buildinf:`` magic, dep lines)
- Ruby: ``**/specifications/*.gemspec`` (regex name/version extraction)
- .NET: ``**/*.deps.json`` (libraries section, type=package)

Whiteout handling: OCI spec uses ``.wh.`` prefix files to signal deletion.
The parser tracks whiteout paths from each layer and skips package detection
on paths that were deleted in subsequent layers.

CLI usage::

    agent-bom scan --image-tar myapp.tar"""

from __future__ import annotations

import json
import lzma
import tarfile
import zlib
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import IO, Any

from agent_bom.coverage import record_scan_input_warning
from agent_bom.models import Package
from agent_bom.parsers.gpu_stack import finalize_gpu_stack
from agent_bom.parsers.image_runtimes import finalize_image_runtimes, seed_image_runtimes
from agent_bom.parsers.oci_extractors import _LAYER_PACKAGE_STAGES
from agent_bom.parsers.oci_io import (
    _max_json_member_bytes,
    _max_layer_compressed_bytes,
    _read_json_member_from_tar,
    _read_json_path_limited,
    _resolve_tar_member,
    _safe_tar_names,
)
from agent_bom.parsers.oci_layer import _apply_detected_distro, _layer_whiteouts, _LayerScan, _read_os_release_from_layer
from agent_bom.parsers.oci_metadata import _MAX_LEGACY_RPMDB_BYTES as _MAX_LEGACY_RPMDB_BYTES
from agent_bom.parsers.oci_metadata import _RPM_HDR_MAGIC as _RPM_HDR_MAGIC
from agent_bom.parsers.oci_metadata import _RPM_TYPE_INT32 as _RPM_TYPE_INT32
from agent_bom.parsers.oci_metadata import _RPM_TYPE_STRING as _RPM_TYPE_STRING
from agent_bom.parsers.oci_metadata import _RPMTAG_EPOCH as _RPMTAG_EPOCH
from agent_bom.parsers.oci_metadata import _RPMTAG_NAME as _RPMTAG_NAME
from agent_bom.parsers.oci_metadata import _RPMTAG_RELEASE as _RPMTAG_RELEASE
from agent_bom.parsers.oci_metadata import _RPMTAG_VERSION as _RPMTAG_VERSION
from agent_bom.parsers.oci_metadata import LayerMetadata as LayerMetadata
from agent_bom.parsers.oci_metadata import _build_layer_metadata as _build_layer_metadata
from agent_bom.parsers.oci_metadata import _normalize_dockerfile_instruction as _normalize_dockerfile_instruction
from agent_bom.parsers.oci_metadata import _normalize_layer_id as _normalize_layer_id
from agent_bom.parsers.oci_metadata import _parse_legacy_rpmdb_bytes as _parse_legacy_rpmdb_bytes
from agent_bom.parsers.oci_metadata import _parse_rfc822_name_version as _parse_rfc822_name_version
from agent_bom.parsers.oci_metadata import _parse_rpm_header_blob as _parse_rpm_header_blob
from agent_bom.parsers.oci_metadata import is_node_package_manifest_path as is_node_package_manifest_path
from agent_bom.parsers.oci_stream import LayerLimitError, ScanBudget, open_bounded_layer
from agent_bom.parsers.oci_types import OCIInputWarning, OCIManifest, OCIParseError, OCIParseResult, _append_oci_warning


def _extract_packages_from_layer(
    layer_tf: tarfile.TarFile,
    packages_by_key: dict[tuple[str, str], Package],
    packages: list[Package],
    deleted_paths: set[str],
    layer: LayerMetadata,
    warnings: list[str] | None = None,
    coverage_warnings: list[OCIInputWarning] | None = None,
    *,
    budget: ScanBudget | None = None,
) -> set[str]:
    """Extract packages from an open layer TarFile.

    Args:
        layer_tf: Open TarFile for the layer.
        packages_by_key: Mutable package map keyed by (name, ecosystem).
        packages: Mutable list of packages — updated in place.
        deleted_paths: Set of paths deleted in LATER layers (whiteouts already processed).
        layer: Layer provenance metadata for this concrete tar blob.
        warnings: Optional mutable list for non-fatal parser diagnostics.
        coverage_warnings: Optional structured diagnostics for incomplete inputs.
        budget: Optional scan budget, checked between extraction stages.

    Returns:
        Set of paths marked as whiteout in THIS layer (for caller to accumulate).
    """
    # `_safe_tar_names` drops traversal, absolute, NUL-injected and link members.
    names = _safe_tar_names(layer_tf)
    whiteouts = _layer_whiteouts(names)
    scan = _LayerScan(layer_tf, names, deleted_paths, layer, packages_by_key, packages, warnings, coverage_warnings)
    for stage in _LAYER_PACKAGE_STAGES:
        if budget is not None:
            budget.check()
        stage(scan)
    return whiteouts


def _occurrence_whiteout_deleted(
    package_path: str | None,
    layer_index: int,
    whiteouts_by_index: dict[int, set[str]],
) -> bool:
    """Return True iff ``package_path`` is removed by a whiteout in a HIGHER layer.

    Per the OCI overlay spec a whiteout deletes paths from layers *below* it
    only. A file re-created in a higher layer therefore survives a lower-layer
    whiteout for the same path. Applying whiteouts as a post-filter scoped to
    strictly-higher layer indices captures both cases: genuine deletion (file in
    a low layer, whiteout above it) and re-add (file in the same or a higher
    layer than the whiteout — kept).
    """
    if not package_path:
        return False
    for whiteout_layer, paths in whiteouts_by_index.items():
        if whiteout_layer <= layer_index:
            continue
        for w in paths:
            if w.endswith("/"):
                if package_path == w[:-1] or package_path.startswith(w):
                    return True
            elif package_path == w or package_path.startswith(w + "/"):
                return True
    return False


def _drop_whiteout_deleted_packages(
    packages: list[Package],
    whiteouts_by_index: dict[int, set[str]],
) -> list[Package]:
    """Drop packages whose every occurrence was deleted by a higher-layer whiteout."""
    if not whiteouts_by_index:
        return packages
    kept: list[Package] = []
    for pkg in packages:
        occurrences = pkg.occurrences
        if not occurrences:
            kept.append(pkg)
            continue
        survivors = [occ for occ in occurrences if not _occurrence_whiteout_deleted(occ.package_path, occ.layer_index, whiteouts_by_index)]
        if survivors:
            pkg.occurrences = survivors
            kept.append(pkg)
    return kept


def _parse_docker_save_manifest(tf: tarfile.TarFile) -> list[OCIManifest]:
    """Parse manifest.json from a Docker save tarball."""
    try:
        member = tf.getmember("manifest.json")
        if member.size > _max_json_member_bytes():
            raise OCIParseError("manifest.json exceeds parser size limit")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("manifest.json is not a regular file")
        data = f.read(member.size + 1)
        if len(data) > _max_json_member_bytes():
            raise OCIParseError("manifest.json exceeds parser size limit")
        raw = json.loads(data.decode("utf-8"))
    except KeyError:
        raise OCIParseError("No manifest.json found — not a Docker save tarball")
    except json.JSONDecodeError as e:
        raise OCIParseError(f"Invalid manifest.json: {e}")

    manifests: list[OCIManifest] = []
    for entry in raw:
        manifests.append(
            OCIManifest(
                config_digest=entry.get("Config", ""),
                repo_tags=entry.get("RepoTags") or [],
                layer_paths=entry.get("Layers", []),
            )
        )
    return manifests


@dataclass
class _ImageWalk:
    """Accumulates one image's packages across layers under a shared scan budget."""

    config: dict | None
    budget: ScanBudget = field(default_factory=ScanBudget.from_env)
    packages_by_key: dict[tuple[str, str], Package] = field(default_factory=dict)
    packages: list[Package] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage_warnings: list[OCIInputWarning] = field(default_factory=list)
    whiteouts_by_index: dict[int, set[str]] = field(default_factory=dict)
    distro_name: str | None = None
    distro_version: str | None = None

    def __post_init__(self) -> None:
        seed_image_runtimes(self.config, self.packages_by_key, self.packages)

    def gap(self, layer_path: str, reason: str, detail: str) -> None:
        _append_oci_warning(
            self.warnings,
            self.coverage_warnings,
            path=layer_path,
            reason=reason,
            detail=detail,
            message=f"Layer {layer_path} skipped: {detail}",
        )

    def scan(self, layer_path: str, layer: LayerMetadata, source: IO[bytes], compressed_size: int, outer: object | None = None) -> None:
        """Extract packages from one layer; every bound it crosses becomes a coverage gap."""
        try:
            with open_bounded_layer(source, compressed_size, self.budget, outer=outer) as layer_tf:
                distro_name, distro_version = _read_os_release_from_layer(layer_tf, set())
                self.distro_name = distro_name or self.distro_name
                self.distro_version = distro_version or self.distro_version
                whiteouts = _extract_packages_from_layer(
                    layer_tf,
                    self.packages_by_key,
                    self.packages,
                    set(),
                    layer,
                    self.warnings,
                    self.coverage_warnings,
                    budget=self.budget,
                )
                if whiteouts:
                    self.whiteouts_by_index.setdefault(layer.layer_index, set()).update(whiteouts)
        except LayerLimitError as exc:
            self.gap(layer_path, exc.reason, exc.detail)
        except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError):
            self.gap(layer_path, "oci_layer_parse_error", "Container layer archive could not be parsed; image inventory is incomplete.")

    def finish(self) -> list[Package]:
        packages = _drop_whiteout_deleted_packages(self.packages, self.whiteouts_by_index)
        packages = finalize_gpu_stack(finalize_image_runtimes(packages), "image_scan")
        _apply_detected_distro(packages, self.distro_name, self.distro_version)
        return packages


def _parse_layers_from_tarball(
    outer_tf: tarfile.TarFile,
    layer_paths: list[str],
    layer_metadata: list[LayerMetadata] | None = None,
    config: dict | None = None,
) -> tuple[list[Package], list[str], list[OCIInputWarning]]:
    """Stream each layer out of the outer tarball and extract packages.

    Layers are processed in order (base → top). Whiteouts are applied as a
    post-filter scoped to strictly-higher layers (see
    ``_drop_whiteout_deleted_packages``), so a file re-created in a higher
    layer is not wrongly suppressed by a lower-layer whiteout.

    Returns:
        (packages, warnings, coverage_warnings)
    """
    walk = _ImageWalk(config)
    layer_metadata = layer_metadata or _build_layer_metadata(layer_paths)
    for layer_path, layer in zip(layer_paths, layer_metadata, strict=False):
        member = _resolve_tar_member(outer_tf, layer_path)
        if member is None:
            walk.gap(layer_path, "oci_layer_missing", "Container layer was not present; image inventory is incomplete.")
            continue
        if member.size > _max_layer_compressed_bytes():
            walk.gap(
                layer_path,
                "oci_layer_size_limit",
                "Container layer exceeds the compressed-size safety limit; image inventory is incomplete.",
            )
            continue
        layer_fobj = outer_tf.extractfile(member)
        if layer_fobj is None:
            walk.gap(layer_path, "oci_layer_unreadable", "Container layer could not be read safely; image inventory is incomplete.")
            continue
        walk.scan(layer_path, layer, layer_fobj, member.size, outer=outer_tf.fileobj)
    return walk.finish(), walk.warnings, walk.coverage_warnings


def _parse_oci_layout_manifest_from_tar(tf: tarfile.TarFile) -> tuple[dict, list[str], dict | None]:
    """Parse index/manifest/config from an OCI image layout tarball."""
    try:
        member = _resolve_tar_member(tf, "index.json")
        if member is None:
            raise OCIParseError("No index.json found — not an OCI image layout tarball")
        if member.size > _max_json_member_bytes():
            raise OCIParseError("index.json exceeds parser size limit")
        f = tf.extractfile(member)
        if f is None:
            raise OCIParseError("index.json is not a regular file")
        data = f.read(member.size + 1)
        if len(data) > _max_json_member_bytes():
            raise OCIParseError("index.json exceeds parser size limit")
        index = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise OCIParseError(f"Invalid index.json: {e}")

    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError("No manifests in OCI index.json")

    manifest_digest = manifests[0].get("digest", "")
    if not manifest_digest.startswith("sha256:"):
        raise OCIParseError(f"Unsupported manifest digest: {manifest_digest}")

    manifest_hash = manifest_digest[len("sha256:") :]
    blob_path = f"blobs/sha256/{manifest_hash}"
    manifest = _read_json_member_from_tar(tf, blob_path)
    if manifest is None:
        raise OCIParseError(f"Failed to read OCI manifest blob: {blob_path}")

    layer_paths = [
        f"blobs/sha256/{digest[len('sha256:') :]}"
        for layer in manifest.get("layers", [])
        if (digest := layer.get("digest", "")).startswith("sha256:")
    ]

    config: dict | None = None
    config_digest = manifest.get("config", {}).get("digest", "")
    if config_digest.startswith("sha256:"):
        config = _read_json_member_from_tar(tf, f"blobs/sha256/{config_digest[len('sha256:') :]}")

    return manifest, layer_paths, config


def parse_oci_tarball(path: Path) -> OCIParseResult:
    """Parse an OCI image tarball (Docker save or OCI layout format).

    Auto-detects the format by checking for ``manifest.json`` (Docker save)
    or ``index.json`` (OCI layout) inside the tarball.

    Args:
        path: Path to the ``.tar`` or ``.tar.gz`` file.

    Returns:
        OCIParseResult with packages, strategy, layer count, and any warnings.

    Raises:
        OCIParseError: If the tarball cannot be parsed.
    """
    if not path.exists():
        raise OCIParseError(f"File not found: {path}")

    try:
        outer_tf = tarfile.open(str(path), mode="r:*")
    except tarfile.TarError as e:
        raise OCIParseError(f"Cannot open tarball: {e}")

    with outer_tf:
        names = outer_tf.getnames()

        # Detect format
        if "manifest.json" in names or "./manifest.json" in names:
            # Docker save format
            try:
                manifests = _parse_docker_save_manifest(outer_tf)
            except OCIParseError:
                raise
            if not manifests:
                return OCIParseResult(
                    packages=[],
                    strategy="oci-tarball",
                    layer_count=0,
                    warnings=["Empty manifest.json"],
                    coverage_warnings=[
                        OCIInputWarning(
                            path="manifest.json",
                            reason="oci_manifest_empty",
                            detail="Container manifest contains no images; image inventory is incomplete.",
                        )
                    ],
                )
            # Use first image (most users save one image)
            manifest = manifests[0]
            config = _read_json_member_from_tar(outer_tf, manifest.config_digest)
            layer_metadata = _build_layer_metadata(manifest.layer_paths, config)
            packages, warnings, coverage_warnings = _parse_layers_from_tarball(outer_tf, manifest.layer_paths, layer_metadata, config)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(manifest.layer_paths),
                image_tags=manifest.repo_tags,
                warnings=warnings,
                coverage_warnings=coverage_warnings,
            )

        elif "index.json" in names or "./index.json" in names:
            # OCI image layout format
            try:
                _manifest, layer_paths, config = _parse_oci_layout_manifest_from_tar(outer_tf)
            except OCIParseError:
                raise
            layer_metadata = _build_layer_metadata(layer_paths, config)
            packages, warnings, coverage_warnings = _parse_layers_from_tarball(outer_tf, layer_paths, layer_metadata, config)
            return OCIParseResult(
                packages=packages,
                strategy="oci-tarball",
                layer_count=len(layer_paths),
                warnings=warnings,
                coverage_warnings=coverage_warnings,
            )

        else:
            raise OCIParseError(
                "Unrecognized image tarball format: neither manifest.json (Docker save) nor index.json (OCI layout) found at tarball root."
            )


def parse_oci_layout_dir(path: Path) -> OCIParseResult:
    """Parse an OCI image layout directory (from skopeo copy --dest-dir, crane pull --format=oci).

    Args:
        path: Path to the directory containing ``index.json`` and ``blobs/`` subdirectory.

    Returns:
        OCIParseResult with packages, strategy, and any warnings.

    Raises:
        OCIParseError: If the directory cannot be parsed.
    """
    if not path.is_dir():
        raise OCIParseError(f"Not a directory: {path}")

    index_path = path / "index.json"
    if not index_path.exists():
        raise OCIParseError(f"index.json not found in {path}")

    index = _read_json_path_limited(index_path)
    if not isinstance(index, dict):
        raise OCIParseError("Failed to read index.json")

    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError("No manifests in OCI index.json")

    manifest_digest = manifests[0].get("digest", "")
    if not manifest_digest.startswith("sha256:"):
        raise OCIParseError(f"Unsupported manifest digest: {manifest_digest}")

    manifest_hash = manifest_digest[len("sha256:") :]
    manifest_blob = path / "blobs" / "sha256" / manifest_hash
    if not manifest_blob.exists():
        raise OCIParseError(f"Manifest blob not found: {manifest_blob}")

    manifest = _read_json_path_limited(manifest_blob)
    if not isinstance(manifest, dict):
        raise OCIParseError("Failed to read manifest blob")

    layer_digests = [
        digest[len("sha256:") :] for layer in manifest.get("layers", []) if (digest := layer.get("digest", "")).startswith("sha256:")
    ]
    layer_paths = [f"blobs/sha256/{layer_hash}" for layer_hash in layer_digests]
    config: dict | None = None
    config_digest = manifest.get("config", {}).get("digest", "")
    if config_digest.startswith("sha256:"):
        config_blob = path / "blobs" / "sha256" / config_digest[len("sha256:") :]
        if config_blob.exists():
            maybe_config = _read_json_path_limited(config_blob)
            config = maybe_config if isinstance(maybe_config, dict) else None
    layer_metadata = _build_layer_metadata(layer_paths, config)

    walk = _ImageWalk(config)
    for layer_hash, layer in zip(layer_digests, layer_metadata, strict=False):
        layer_path = f"blobs/sha256/{layer_hash}"
        blob_path = path / "blobs" / "sha256" / layer_hash
        if not blob_path.is_file():
            walk.gap(layer_path, "oci_layer_missing", "Container layer was not present; image inventory is incomplete.")
            continue
        with blob_path.open("rb") as blob:
            walk.scan(layer_path, layer, blob, blob_path.stat().st_size)
    packages, warnings, coverage_warnings = walk.finish(), walk.warnings, walk.coverage_warnings

    return OCIParseResult(
        packages=packages,
        strategy="oci-layout-dir",
        layer_count=len(layer_digests),
        warnings=warnings,
        coverage_warnings=coverage_warnings,
    )


def scan_oci(path: str | Path) -> tuple[list[Package], str]:
    """Scan an OCI image tarball or layout directory. Returns (packages, strategy).

    Auto-detects format:
    - File: parses as Docker save or OCI layout tarball.
    - Directory: parses as OCI image layout directory.

    Raises:
        OCIParseError: If the path cannot be parsed.
    """
    p = Path(path)
    if p.is_dir():
        result = parse_oci_layout_dir(p)
    else:
        result = parse_oci_tarball(p)

    for warning in result.coverage_warnings:
        record_scan_input_warning(
            scanner="oci",
            path=warning.path,
            reason=warning.reason,
            detail=warning.detail,
        )

    return result.packages, result.strategy


_EXPORTS = {
    "_logger": "agent_bom.parsers.oci_io",
    "_MAX_JSON_MEMBER_BYTES": "agent_bom.parsers.oci_io",
    "_MAX_LAYER_UNCOMPRESSED_BYTES": "agent_bom.parsers.oci_io",
    "_MAX_JAR_UNCOMPRESSED_BYTES": "agent_bom.parsers.oci_io",
    "_MAX_DECOMPRESSION_RATIO": "agent_bom.parsers.oci_io",
    "_env_int": "agent_bom.parsers.oci_io",
    "_max_jar_uncompressed_bytes": "agent_bom.parsers.oci_io",
    "_max_decompression_ratio": "agent_bom.parsers.oci_io",
    "_decompression_ratio_exceeded": "agent_bom.parsers.oci_io",
    "_max_layer_uncompressed_bytes": "agent_bom.parsers.oci_io",
    "_is_safe_tar_member_name": "agent_bom.parsers.oci_io",
    "_safe_getmember": "agent_bom.parsers.oci_io",
    "_safe_extractfile": "agent_bom.parsers.oci_io",
    "_WHITEOUT_PREFIX": "agent_bom.parsers.oci_types",
    "_OPAQUE_WHITEOUT": "agent_bom.parsers.oci_types",
    "_JAR_EXT_RE": "agent_bom.parsers.oci_types",
    "_JAR_DIR_HINTS": "agent_bom.parsers.oci_types",
    "_JAR_MAX_BYTES": "agent_bom.parsers.oci_types",
    "_GO_BUILDINFO_MAGIC": "agent_bom.parsers.oci_types",
    "_GO_BIN_DIR_RE": "agent_bom.parsers.oci_types",
    "_GO_BIN_MAX_READ": "agent_bom.parsers.oci_types",
    "_GO_DEP_LINE_RE": "agent_bom.parsers.oci_types",
    "_GEMSPEC_PATH_RE": "agent_bom.parsers.oci_types",
    "_GEMSPEC_NAME_RE": "agent_bom.parsers.oci_types",
    "_GEMSPEC_VER_RE": "agent_bom.parsers.oci_types",
    "_RPM_SQLITE_PATHS": "agent_bom.parsers.oci_types",
    "_RPM_BDB_PATHS": "agent_bom.parsers.oci_types",
    "_RPM_NDB_PATHS": "agent_bom.parsers.oci_types",
    "_RPM_MANIFEST_PATHS": "agent_bom.parsers.oci_types",
    "_RPM_MANIFEST_RE": "agent_bom.parsers.oci_types",
    "_RPMTAG_ARCH": "agent_bom.parsers.oci_types",
    "_PACKAGE_METADATA_WARNING_DETAIL": "agent_bom.parsers.oci_types",
    "_mark_package_metadata_gap": "agent_bom.parsers.oci_types",
    "_zip_uncompressed_size": "agent_bom.parsers.oci_io",
    "_zip_compressed_size": "agent_bom.parsers.oci_io",
    "_query_legacy_rpmdb": "agent_bom.parsers.oci_io",
    "_add_package": "agent_bom.parsers.oci_layer",
    "_parse_members": "agent_bom.parsers.oci_extractors",
    "_present_candidates": "agent_bom.parsers.oci_extractors",
    "_extract_python_metadata": "agent_bom.parsers.oci_extractors",
    "_add_node_manifest": "agent_bom.parsers.oci_extractors",
    "_extract_node_manifests": "agent_bom.parsers.oci_extractors",
    "_add_dpkg_entries": "agent_bom.parsers.oci_extractors",
    "_add_apk_entries": "agent_bom.parsers.oci_extractors",
    "_extract_stanza_database": "agent_bom.parsers.oci_extractors",
    "_extract_dpkg_status": "agent_bom.parsers.oci_extractors",
    "_extract_apk_installed": "agent_bom.parsers.oci_extractors",
    "_add_rpm": "agent_bom.parsers.oci_extractors",
    "_add_rpm_manifest_lines": "agent_bom.parsers.oci_extractors",
    "_extract_rpm_manifest": "agent_bom.parsers.oci_extractors",
    "_add_rpm_sqlite_rows": "agent_bom.parsers.oci_extractors",
    "_extract_rpm_sqlite": "agent_bom.parsers.oci_extractors",
    "_extract_legacy_rpmdb": "agent_bom.parsers.oci_extractors",
    "_sized_jar_member": "agent_bom.parsers.oci_extractors",
    "_jar_within_limits": "agent_bom.parsers.oci_extractors",
    "_read_jar_pairs": "agent_bom.parsers.oci_extractors",
    "_add_jar_pom_properties": "agent_bom.parsers.oci_extractors",
    "_add_jar_manifest": "agent_bom.parsers.oci_extractors",
    "_add_jar_packages": "agent_bom.parsers.oci_extractors",
    "_extract_jars": "agent_bom.parsers.oci_extractors",
    "_add_go_buildinfo": "agent_bom.parsers.oci_extractors",
    "_extract_go_binaries": "agent_bom.parsers.oci_extractors",
    "_add_gemspec": "agent_bom.parsers.oci_extractors",
    "_extract_gemspecs": "agent_bom.parsers.oci_extractors",
    "_add_deps_json": "agent_bom.parsers.oci_extractors",
    "_extract_deps_json": "agent_bom.parsers.oci_extractors",
    "_add_composer_lock": "agent_bom.parsers.oci_extractors",
    "_extract_composer_locks": "agent_bom.parsers.oci_extractors",
    "_add_cargo_lock": "agent_bom.parsers.oci_extractors",
    "_extract_cargo_locks": "agent_bom.parsers.oci_extractors",
    "_add_swift_resolved": "agent_bom.parsers.oci_extractors",
    "_extract_swift_resolved": "agent_bom.parsers.oci_extractors",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
