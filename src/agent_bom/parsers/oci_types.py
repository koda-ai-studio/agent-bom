"""OCI result types, coverage warnings and metadata path patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agent_bom.models import Package

_WHITEOUT_PREFIX = ".wh."


_OPAQUE_WHITEOUT = ".wh..wh..opq"


_JAR_EXT_RE = re.compile(r"\.(jar|war|ear)$", re.IGNORECASE)


_JAR_DIR_HINTS = ("java", "jvm", "/app/", "/opt/", "/srv/", "/usr/local/", "/usr/share/", "/home/")


_JAR_MAX_BYTES = 150 * 1024 * 1024


_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


_GO_BIN_DIR_RE = re.compile(r"^\.?/?(usr/(local/)?s?bin|go/bin|usr/local/go/bin|opt/go/bin)/")


_GO_BIN_MAX_READ = 8 * 1024 * 1024


_GO_DEP_LINE_RE = re.compile(rb"dep\t([^\t\n]+)\t(v[^\t\n\s]+)")


_GEMSPEC_PATH_RE = re.compile(r"specifications/([^/]+)\.gemspec$")


_GEMSPEC_NAME_RE = re.compile(r'\.name\s*=\s*["\']([^"\']+)["\']')


_GEMSPEC_VER_RE = re.compile(r'\.version\s*=\s*(?:Gem::Version\.new\()?["\']([^"\']+)["\']')


_RPM_SQLITE_PATHS = ("var/lib/rpm/rpmdb.sqlite", "./var/lib/rpm/rpmdb.sqlite")


_RPM_BDB_PATHS = ("var/lib/rpm/Packages", "./var/lib/rpm/Packages")


_RPM_NDB_PATHS = ("var/lib/rpm/Packages.db", "./var/lib/rpm/Packages.db")


_RPM_MANIFEST_PATHS = ("var/log/installed-rpms", "./var/log/installed-rpms")


_RPM_MANIFEST_RE = re.compile(r"^(?P<name>.+)-(?P<version>[0-9][^-]*)-(?P<release>\S+)$")


_RPMTAG_ARCH = 1022


@dataclass
class OCIManifest:
    """Parsed image manifest (Docker save or OCI layout)."""

    config_digest: str
    repo_tags: list[str]
    layer_paths: list[str]  # paths inside the outer tarball


@dataclass(frozen=True)
class OCIInputWarning:
    """One container input that could not be completely inspected."""

    path: str
    reason: str
    detail: str


@dataclass
class OCIParseResult:
    """Result of parsing an OCI image tarball or directory."""

    packages: list[Package]
    strategy: str  # "oci-tarball" | "oci-layout-dir"
    layer_count: int
    image_tags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage_warnings: list[OCIInputWarning] = field(default_factory=list)


_PACKAGE_METADATA_WARNING_DETAIL = "Container package metadata could not be parsed; image inventory is incomplete."


def _append_oci_warning(
    warnings: list[str],
    coverage_warnings: list[OCIInputWarning],
    *,
    path: str,
    reason: str,
    detail: str,
    message: str | None = None,
) -> None:
    """Preserve the parser diagnostic and its structured coverage consequence."""
    warnings.append(message or f"{path}: {detail}")
    coverage_warnings.append(OCIInputWarning(path=path, reason=reason, detail=detail))


def _mark_package_metadata_gap(
    warnings: list[str] | None,
    coverage_warnings: list[OCIInputWarning] | None,
    member_path: str,
) -> None:
    if warnings is None or coverage_warnings is None:
        return
    _append_oci_warning(
        warnings,
        coverage_warnings,
        path=member_path,
        reason="package_metadata_parse_error",
        detail=_PACKAGE_METADATA_WARNING_DETAIL,
        message=f"Container package metadata could not be parsed: {member_path}",
    )


class OCIParseError(Exception):
    """Raised when an OCI image cannot be parsed."""
