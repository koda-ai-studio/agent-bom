"""Distro context for SBOM OS packages, read from the Package URL.

An image scan learns an OS package's distro from ``/etc/os-release`` (``ID`` +
``VERSION_ID``). An SBOM carries the same facts in the purl: the namespace
names the distro (``pkg:rpm/redhat/...``, ``pkg:deb/debian/...``) and the
``distro`` qualifier names the release (``distro=rhel-9.4``, ``distro=el9``,
``distro=debian-12``, or a bare ``distro=3.19.1`` for apk). Both are mapped
onto os-release ``ID``/``VERSION_ID`` values so advisory routing
(:func:`agent_bom.scanners.package_matching._resolve_osv_ecosystems`) treats an
SBOM package exactly like the same package found in an image.

A release that is not numeric (a codename such as ``bookworm``) is left unset
rather than guessed.
"""

from __future__ import annotations

import re

from packageurl import PackageURL

from agent_bom.models import Package

_OS_PURL_TYPES = frozenset({"rpm", "deb", "apk"})

# purl namespace / qualifier distro name -> /etc/os-release ID
_OS_RELEASE_ID = {
    "redhat": "rhel",
    "red hat": "rhel",
    "rhel": "rhel",
    "centos": "centos",
    "rocky": "rocky",
    "rockylinux": "rocky",
    "almalinux": "almalinux",
    "alma": "almalinux",
    "amzn": "amzn",
    "amazon": "amzn",
    "amazonlinux": "amzn",
    "ol": "ol",
    "oracle": "ol",
    "oraclelinux": "ol",
    "fedora": "fedora",
    "opensuse": "opensuse-leap",
    "opensuse-leap": "opensuse-leap",
    "opensuse-tumbleweed": "opensuse-tumbleweed",
    "suse": "sles",
    "sles": "sles",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "alpine": "alpine",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
}
_NAMED_RELEASE_RE = re.compile(r"^(?P<name>[a-z][a-z-]*?)-(?P<version>\d[0-9a-z._]*)$")
_EL_RELEASE_RE = re.compile(r"^el(?P<major>\d+)(?:[._].*)?$")
_BARE_RELEASE_RE = re.compile(r"^v?(?P<version>\d[0-9a-z._]*)$")


def _os_release_id(name: str | None) -> str | None:
    key = (name or "").strip().lower()
    return _OS_RELEASE_ID.get(key, key or None)


def _parse_release(qualifier: str) -> tuple[str | None, str | None]:
    """``distro`` qualifier -> (distro name or None, numeric release or None)."""
    value = qualifier.strip().lower()
    if match := _NAMED_RELEASE_RE.match(value):
        return match["name"], match["version"]
    if match := _EL_RELEASE_RE.match(value):
        return None, match["major"]
    if match := _BARE_RELEASE_RE.match(value):
        return None, match["version"]
    return None, None


def purl_distro(purl: str | None) -> tuple[str | None, str | None]:
    """os-release ``(ID, VERSION_ID)`` for an OS-package purl, ``(None, None)`` otherwise."""
    if not purl or not purl.startswith("pkg:"):
        return None, None
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None, None
    if parsed.type not in _OS_PURL_TYPES:
        return None, None
    qualifiers = parsed.qualifiers if isinstance(parsed.qualifiers, dict) else {}
    qualifier_name, release = _parse_release(str(qualifiers.get("distro") or ""))
    name = _os_release_id(qualifier_name) or _os_release_id(parsed.namespace)
    return name, release


def apply_purl_distro(packages: list[Package]) -> list[Package]:
    """Stamp purl-derived distro context onto OS packages that lack their own; returns ``packages``."""
    for package in packages:
        if package.ecosystem not in _OS_PURL_TYPES or (package.distro_name and package.distro_version):
            continue
        name, release = purl_distro(package.purl)
        package.distro_name = package.distro_name or name
        package.distro_version = package.distro_version or release
    return packages
