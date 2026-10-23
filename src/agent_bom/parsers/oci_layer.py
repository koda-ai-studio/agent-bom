"""Layer-scoped package accumulation and whiteout evidence."""

from __future__ import annotations

import tarfile
from dataclasses import dataclass
from typing import Optional

from agent_bom.models import Package, PackageOccurrence
from agent_bom.parsers.oci_io import _logger, _safe_getmember
from agent_bom.parsers.oci_metadata import LayerMetadata as LayerMetadata
from agent_bom.parsers.oci_types import _OPAQUE_WHITEOUT, _WHITEOUT_PREFIX, OCIInputWarning, _mark_package_metadata_gap


def _add_package(
    packages_by_key: dict[tuple[str, str], Package],
    packages: list[Package],
    name: str,
    version: str,
    ecosystem: str,
    purl: Optional[str] = None,
    *,
    source_package: str | None = None,
    distro_name: str | None = None,
    distro_version: str | None = None,
    layer: LayerMetadata | None = None,
    package_path: str | None = None,
) -> None:
    key = (name.lower(), ecosystem)
    package = packages_by_key.get(key)
    if package is None:
        package = Package(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=purl or f"pkg:{ecosystem}/{name}@{version}",
            is_direct=False,
            resolved_from_registry=False,
            source_package=source_package,
            distro_name=distro_name,
            distro_version=distro_version,
        )
        packages_by_key[key] = package
        packages.append(package)
    else:
        # When a later layer rewrites package metadata (common for lockfiles and
        # package DBs), keep the final image view aligned to the latest version.
        if version and package.version != version:
            package.version = version
            package.purl = purl or f"pkg:{ecosystem}/{name}@{version}"
            package.source_package = source_package
            package.distro_name = distro_name or package.distro_name
            package.distro_version = distro_version or package.distro_version
            package.occurrences.clear()
        elif purl and package.purl != purl:
            package.purl = purl
        if source_package is not None:
            package.source_package = source_package
        if distro_name is not None:
            package.distro_name = distro_name
        if distro_version is not None:
            package.distro_version = distro_version

    if layer is None:
        return

    occurrence = PackageOccurrence(
        layer_index=layer.layer_index,
        layer_id=layer.layer_id,
        layer_path=layer.layer_path,
        package_path=package_path,
        created_by=layer.created_by,
        dockerfile_instruction=layer.dockerfile_instruction,
    )
    occurrence_key = (occurrence.layer_index, occurrence.layer_id, occurrence.package_path or "")
    existing_keys = {(occ.layer_index, occ.layer_id, occ.package_path or "") for occ in package.occurrences}
    if occurrence_key not in existing_keys:
        package.occurrences.append(occurrence)


def _read_os_release_from_layer(layer_tf: tarfile.TarFile, deleted_paths: set[str]) -> tuple[str | None, str | None]:
    """Read distro metadata from ``os-release`` inside a layer.

    Probes both the canonical ``usr/lib/os-release`` location and the historic
    ``etc/os-release`` path. On Debian/Ubuntu ``/etc/os-release`` is a symlink
    to ``/usr/lib/os-release``; the parser refuses to follow symlinks, so the
    real file under ``usr/lib`` must be probed directly or distro detection
    silently fails (which mis-routes OS-package CVE matching to the wrong
    distribution release).
    """
    for os_release_path in (
        "etc/os-release",
        "./etc/os-release",
        "usr/lib/os-release",
        "./usr/lib/os-release",
    ):
        if os_release_path in deleted_paths:
            continue
        member = _safe_getmember(layer_tf, os_release_path)
        if member is None:
            # Missing, symlinked (refused), or unsafe name. Try next candidate.
            continue
        try:
            f = layer_tf.extractfile(member)
            if f is None:
                continue
            distro_name: str | None = None
            distro_version: str | None = None
            for raw_line in f:
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if line.startswith("ID="):
                    distro_name = line.split("=", 1)[1].strip().strip('"').strip("'").lower() or None
                elif line.startswith("VERSION_ID="):
                    distro_version = line.split("=", 1)[1].strip().strip('"').strip("'") or None
            return distro_name, distro_version
        except (tarfile.TarError, OSError, UnicodeDecodeError) as e:
            _logger.debug("Failed to parse os-release %s: %s: %s", os_release_path, type(e).__name__, e)
    return None, None


@dataclass
class _LayerScan:
    """One layer's member names plus the sinks every package stage writes to."""

    layer_tf: tarfile.TarFile
    names: set[str]
    deleted_paths: set[str]
    layer: LayerMetadata
    packages_by_key: dict[tuple[str, str], Package]
    packages: list[Package]
    warnings: list[str] | None
    coverage_warnings: list[OCIInputWarning] | None

    def is_deleted(self, path: str) -> bool:
        if path in self.deleted_paths:
            return True
        # Opaque whiteouts delete whole directories.
        for dp in self.deleted_paths:
            if dp.endswith("/") and path.startswith(dp):
                return True
        return False

    def present(self, path: str) -> bool:
        return path in self.names and not self.is_deleted(path)

    def add(
        self, path: str, name: str, version: str, ecosystem: str, purl: str | None = None, *, source_package: str | None = None
    ) -> None:
        _add_package(
            self.packages_by_key,
            self.packages,
            name,
            version,
            ecosystem,
            purl,
            source_package=source_package,
            layer=self.layer,
            package_path=path,
        )

    def gap(self, path: str) -> None:
        _mark_package_metadata_gap(self.warnings, self.coverage_warnings, path)


def _layer_whiteouts(names: set[str]) -> set[str]:
    whiteouts: set[str] = set()
    for member_name in names:
        base = member_name.split("/")[-1]
        if base == _OPAQUE_WHITEOUT:
            parent = "/".join(member_name.split("/")[:-1])
            whiteouts.add(parent + "/")
        elif base.startswith(_WHITEOUT_PREFIX):
            real_name = base[len(_WHITEOUT_PREFIX) :]
            parent = "/".join(member_name.split("/")[:-1])
            path = f"{parent}/{real_name}" if parent else real_name
            whiteouts.add(path)
    return whiteouts


def _apply_detected_distro(packages: list[Package], name: str | None, version: str | None) -> None:
    """Stamp the image's detected distro onto OS packages that lack their own."""
    for pkg in packages:
        if pkg.ecosystem in {"deb", "apk", "rpm"}:
            pkg.distro_name = pkg.distro_name or name
            pkg.distro_version = pkg.distro_version or version
