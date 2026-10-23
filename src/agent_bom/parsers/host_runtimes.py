"""Source-built language runtimes on hosts and mounted VM snapshots.

Runtimes compiled from source (``make install`` into ``/usr/local``) or unpacked
from vendor tarballs into ``/opt`` are invisible to the distro package
database. Their version is recorded in files the build installs next to the
binary: installed headers, ``rbconfig.rb``, Go's ``VERSION`` and the JDK
``release`` file. PHP and Node also embed a compile-time version string in the
executable, which is searched within a fixed byte budget. Nothing is executed.

Runtime identity (names, purls, NVD CPE vendor:product pairs) is shared with
:mod:`agent_bom.parsers.image_runtimes`, so a runtime found on a host and in an
image is one component with one CPE.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_bom.models import Package
from agent_bom.parsers.gpu_stack import detect_gpu_stack, finalize_gpu_stack
from agent_bom.parsers.image_runtimes import _SPEC_BY_NAME, RuntimeSpec, _distro_duplicate
from agent_bom.parsers.rootfs_files import list_names, read_bounded, regular_file, search_bounded

_DISTRO_ECOSYSTEMS = frozenset({"deb", "rpm", "apk"})
_MAX_TEXT_FILE = 262_144
_BINARY_SCAN_BYTES = 128 * 1024 * 1024
_DOTTED = re.compile(r"[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,4})?")
_PYTHON = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}(?:(?:a|b|rc)[0-9]{1,2})?")


@dataclass(frozen=True)
class _Found:
    version: str
    evidence_type: str
    source_file: str


def _text_define(root: Path, rel: str, pattern: str, grammar: re.Pattern[str]) -> str | None:
    content = read_bounded(root, rel, _MAX_TEXT_FILE)
    match = re.search(pattern.encode(), content or b"", re.MULTILINE)
    version = match[1].decode("ascii", "replace") if match else None
    return version if version and grammar.fullmatch(version) else None


def _binary_string(root: Path, rel: str, pattern: bytes, grammar: re.Pattern[str]) -> str | None:
    match = search_bounded(root, rel, re.compile(pattern), _BINARY_SCAN_BYTES)
    version = match[1].decode("ascii", "replace") if match else None
    return version if version and grammar.fullmatch(version) else None


def _first(*candidates: tuple[Callable[[], str | None], str, str]) -> _Found | None:
    for probe, evidence_type, source_file in candidates:
        version = probe()
        if version:
            return _Found(version, evidence_type, source_file)
    return None


def _php(root: Path) -> list[_Found]:
    binary, header = "usr/local/bin/php", "usr/local/include/php/main/php_version.h"
    if regular_file(root, binary) is None:
        return []
    found = _first(
        (lambda: _text_define(root, header, r'^#\s*define\s+PHP_VERSION\s+"([^"]{1,32})"', _DOTTED), "installed_header", header),
        (lambda: _binary_string(root, binary, rb"X-Powered-By: PHP/([0-9][0-9A-Za-z.:*]{0,40})", _DOTTED), "binary_version_string", binary),
    )
    return [found] if found else []


def _python(root: Path) -> list[_Found]:
    out = []
    for name in list_names(root, "usr/local/bin"):
        branch = re.fullmatch(r"python([0-9]\.[0-9]{1,3})", name)
        if not branch or regular_file(root, f"usr/local/bin/{name}") is None:
            continue
        header = f"usr/local/include/python{branch[1]}/patchlevel.h"
        version = _text_define(root, header, r'^\s*#\s*define\s+PY_VERSION\s+"([^"]{1,32})"', _PYTHON)
        if version and version.startswith(branch[1] + "."):
            out.append(_Found(version, "installed_header", header))
    return out


def _node(root: Path) -> list[_Found]:
    binary, header = "usr/local/bin/node", "usr/local/include/node/node_version.h"
    if regular_file(root, binary) is None:
        return []

    def _from_header() -> str | None:
        parts = [
            _text_define(root, header, rf"^#define NODE_{part}_VERSION ([0-9]{{1,4}})$", re.compile(r"[0-9]+"))
            for part in ("MAJOR", "MINOR", "PATCH")
        ]
        version = ".".join(part for part in parts if part)
        return version if None not in parts and _DOTTED.fullmatch(version) else None

    found = _first(
        (_from_header, "installed_header", header),
        (
            lambda: _binary_string(root, binary, rb"nodejs\.org/download/release/v([0-9][0-9.]{0,40})/", _DOTTED),
            "binary_version_string",
            binary,
        ),
    )
    return [found] if found else []


def _go(root: Path) -> list[_Found]:
    rel = "usr/local/go/VERSION"
    version = _text_define(root, rel, r"\Ago([0-9][0-9.]{0,40})$", re.compile(r"[0-9]{1,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?"))
    return [_Found(version, "version_file", rel)] if version else []


def _ruby(root: Path) -> list[_Found]:
    if regular_file(root, "usr/local/bin/ruby") is None:
        return []
    for api in list_names(root, "usr/local/lib/ruby"):
        for arch in list_names(root, f"usr/local/lib/ruby/{api}"):
            rel = f"usr/local/lib/ruby/{api}/{arch}/rbconfig.rb"
            version = _text_define(root, rel, r'CONFIG\["RUBY_PROGRAM_VERSION"\] = "([^"]{1,32})"', _DOTTED)
            if version:
                return [_Found(version, "version_file", rel)]
    return []


def _java(root: Path) -> list[_Found]:
    out = []
    for name in list_names(root, "opt/java"):
        rel = f"opt/java/{name}/release"
        version = _text_define(root, rel, r'^JAVA_VERSION="([^"]{1,32})"', re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,6}){0,3}"))
        if version:
            out.append(_Found(version, "version_file", rel))
    return out


_PROBES: tuple[tuple[str, Callable[[Path], list[_Found]]], ...] = (
    ("php", _php),
    ("cpython", _python),
    ("node", _node),
    ("go", _go),
    ("ruby", _ruby),
    ("openjdk", _java),
)


def _package(spec: RuntimeSpec, found: _Found) -> Package | None:
    cpe = spec.cpe(found.version)
    if cpe is None:
        return None
    return Package(
        name=spec.name,
        version=found.version,
        ecosystem="generic",
        purl=spec.purl(found.version),
        cpe=cpe,
        is_direct=False,
        resolved_from_registry=False,
        version_evidence=[{"type": found.evidence_type, "source_file": found.source_file}],
        discovery_provenance={
            "source_type": "filesystem_scan",
            "source": "binary" if found.evidence_type == "binary_version_string" else "version-file",
            "observed_via": [found.source_file],
            "confidence": "high",
        },
    )


def detect_host_runtimes(root: Path, existing: Iterable[Package]) -> list[Package]:
    """Source-built runtimes under ``root`` that no distro package already inventories."""
    distro = [pkg for pkg in existing if pkg.ecosystem in _DISTRO_ECOSYSTEMS]
    out: list[Package] = []
    for name, probe in _PROBES:
        spec = _SPEC_BY_NAME[name]
        seen: set[str] = set()
        for found in probe(root):
            if found.version in seen or _distro_duplicate(spec, found.version, distro):
                continue
            package = _package(spec, found)
            if package is not None:
                seen.add(found.version)
                out.append(package)
    return out


def unpackaged_host_components(root: Path, packages: list[Package]) -> list[Package]:
    """``packages`` plus source-built runtimes and the NVIDIA GPU stack found under ``root``."""
    runtimes = detect_host_runtimes(root, packages)
    return finalize_gpu_stack([*packages, *runtimes, *detect_gpu_stack(root)])


def global_node_packages(root: Path) -> list[Package]:
    """Globally installed npm packages under the system ``node_modules`` prefixes."""
    packages: list[Package] = []
    for node_pattern in ("usr/lib/node_modules/*/package.json", "usr/local/lib/node_modules/*/package.json"):
        for pkg_json_path in root.glob(node_pattern):
            try:
                pkg_data = json.loads(pkg_json_path.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            name = pkg_data.get("name", "")
            version = pkg_data.get("version", "")
            if name and version:
                packages.append(Package(name=name, version=version, ecosystem="npm", purl=f"pkg:npm/{name}@{version}", is_direct=True))
    return packages
