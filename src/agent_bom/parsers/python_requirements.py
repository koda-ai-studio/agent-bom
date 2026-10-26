"""PEP 508 requirement strings to declaration-only :class:`Package` objects.

The full specifier set is kept as ``declared_version`` so registry resolution
selects a version the declaration admits (``>=4.7.1,<5`` never resolves to
5.x). Requirements whose environment marker is false for every supported
CPython release are skipped; any other marker is kept and noted, because the
target platform is not known at scan time.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from packaging.markers import Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.version_utils import strip_pip_extras

logger = logging.getLogger(__name__)

_EXACT_OPERATORS = frozenset({"==", "==="})
_PYTHON_ONLY_MARKER_VARS = frozenset({"python_version", "python_full_version"})
_MARKER_VAR_RE = re.compile(
    r"\b(python_version|python_full_version|os_name|sys_platform|platform_\w+|implementation_\w+|extra|dependency_groups)\b"
)
_SUPPORTED_PYTHONS = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14")
_OPTION_TAIL_RE = re.compile(r"\s+--\S.*$")
_LEGACY_SPEC_RE = re.compile(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)")
_BARE_NAME_RE = re.compile(r"([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)(?:\s*;.*)?")
_BARE_PREFIX_RE = re.compile(r"^([a-zA-Z0-9_.-]+(?:\[[^\]]+\])?)")


# PEP 508 direct-URL git reference (``flask @ git+https://…/flask.git@<sha>``)
# and the legacy ``git+https://…#egg=name`` form.
_GIT_DIRECT_URL_RE = re.compile(r"^(?P<name>[a-zA-Z0-9_.-]+)\s*@\s*(?P<url>\S+)$")
_GIT_EGG_RE = re.compile(r"[#&]egg=(?P<name>[a-zA-Z0-9_.-]+)")

_GIT_REF_FLOATING_REASON = (
    "declared as a git URL/SHA reference — a pinned git ref is not a released "
    "version, so any reported version is resolved from the installed host "
    "package, not the pinned ref"
)


def _looks_like_git_requirement(url: str) -> bool:
    lowered = url.lower()
    return lowered.startswith(("git+", "git@", "git://")) or "git+" in lowered


def _with_manifest_location(package: Package, path: Path, line: int) -> Package:
    """Attach the declaration location used by machine-readable outputs."""
    package.version_evidence.append(
        {
            "type": "manifest",
            "source_file": str(path),
            "line": line,
        }
    )
    return package


def _requirement_package(name: str, operator: str, version: str, *, is_direct: bool) -> Package:
    """Build a Package for a ``name<op>version`` declaration line.

    An exact ``==`` pin is reported as the installed version. A range/inequality
    (``>=``/``<``/``~=``/``!=`` or a ``==x.*`` wildcard) does NOT identify an
    installed version — the named bound is a constraint the resolved version may
    even exclude (``<2.3`` excludes 2.3). Emitting ``pkg@<bound>`` as an exact pin
    is a fabricated fact, so a range is recorded as a floating declaration
    reference with lowered confidence instead. Packages come from a declaration
    manifest (no runtime/import proof), so reachability is ``declaration_only``.
    """
    if operator in _EXACT_OPERATORS and "*" not in version:
        return Package(
            name=name,
            version=version,
            ecosystem="pypi",
            purl=f"pkg:pypi/{name}@{version}",
            is_direct=is_direct,
            reachability_evidence="declaration_only",
        )
    return Package(
        name=name,
        version="unknown",
        ecosystem="pypi",
        is_direct=is_direct,
        declared_version=f"{operator}{version}",
        floating_reference=True,
        floating_reference_reason=(
            f"declared as a version constraint ({operator}{version}), not an exact "
            "pin — the installed version is unknown and may differ from the bound"
        ),
        version_confidence="low",
        reachability_evidence="declaration_only",
    )


def _git_reference_package(line: str, *, is_direct: bool = True) -> Package | None:
    """Return a Package for a git-URL requirement line, or None if not one.

    A git reference resolves (at scan time) to whatever the host environment has
    installed, which is *not* an exact match to the pinned ref. Mark it
    ``floating_reference`` with lowered confidence so downstream matching does not
    treat the host-env coincidence as an exact pin.
    """
    direct = _GIT_DIRECT_URL_RE.match(line)
    if direct and _looks_like_git_requirement(direct.group("url")):
        name, url = direct.group("name"), direct.group("url")
    elif _looks_like_git_requirement(line):
        egg = _GIT_EGG_RE.search(line)
        if not egg:
            return None
        name, url = egg.group("name"), line.split()[0]
    else:
        return None
    return Package(
        name=name,
        version="unknown",
        ecosystem="pypi",
        is_direct=is_direct,
        declared_version=url,
        floating_reference=True,
        floating_reference_reason=_GIT_REF_FLOATING_REASON,
        version_confidence="low",
        reachability_evidence="declaration_only",
    )


def clean_requirement_line(line: str) -> str:
    """Strip comments, line continuations and per-requirement pip options."""
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    line = line.rstrip("\\").strip()
    return _OPTION_TAIL_RE.sub("", line).strip()


def _marker_never_applies(marker: Marker) -> bool:
    variables = set(_MARKER_VAR_RE.findall(str(marker)))
    if not variables or not variables <= _PYTHON_ONLY_MARKER_VARS:
        return False
    try:
        return not any(
            marker.evaluate({"python_version": version, "python_full_version": f"{version}.0"}) for version in _SUPPORTED_PYTHONS
        )
    except (UndefinedComparison, UndefinedEnvironmentName):
        return False


def _exact_version(requirement: Requirement) -> str | None:
    specs = list(requirement.specifier)
    if len(specs) == 1 and specs[0].operator in _EXACT_OPERATORS and "*" not in specs[0].version:
        return specs[0].version
    return None


def parse_requirement(text: str, *, is_direct: bool = True) -> Package | None | bool:
    """Return a Package, ``False`` when the marker never applies, or ``None`` when unparseable."""
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        return None
    if requirement.url:
        return None
    if requirement.marker is not None and _marker_never_applies(requirement.marker):
        return False
    package = _package_for(requirement, is_direct=is_direct)
    if requirement.marker is not None:
        package.version_evidence.append({"type": "environment_marker", "marker": str(requirement.marker)})
    return package


def _package_for(requirement: Requirement, *, is_direct: bool) -> Package:
    name = requirement.name
    exact = _exact_version(requirement)
    if exact is not None:
        return Package(
            name=name,
            version=exact,
            ecosystem="pypi",
            purl=f"pkg:pypi/{name}@{exact}",
            is_direct=is_direct,
            reachability_evidence="declaration_only",
        )
    spec = str(requirement.specifier)
    if not spec:
        return Package(name=name, version="unknown", ecosystem="pypi", is_direct=is_direct, reachability_evidence="declaration_only")
    return Package(
        name=name,
        version="unknown",
        ecosystem="pypi",
        is_direct=is_direct,
        declared_version=spec,
        floating_reference=True,
        floating_reference_reason=(
            f"declared as a version constraint ({spec}), not an exact pin — the installed version is unknown and may differ from the bound"
        ),
        version_confidence="low",
        reachability_evidence="declaration_only",
    )


def _unversioned_package(raw_name: str, *, is_direct: bool) -> Package:
    name, _ = strip_pip_extras(raw_name)
    return Package(name=name, version="unknown", ecosystem="pypi", is_direct=is_direct, reachability_evidence="declaration_only")


def bare_name_package(line: str, *, is_direct: bool) -> Package | None:
    """Lenient fallback: the leading distribution name of an unparseable declaration."""
    match = _BARE_PREFIX_RE.match(line)
    return _unversioned_package(match.group(1), is_direct=is_direct) if match else None


def requirement_line_package(line: str, *, is_direct: bool) -> Package | None | bool:
    """One requirement declaration: a Package, ``False`` to skip, ``None`` when malformed."""
    git_pkg = _git_reference_package(line, is_direct=is_direct)
    if git_pkg is not None:
        return git_pkg
    parsed = parse_requirement(line, is_direct=is_direct)
    if parsed is not None:
        return parsed
    legacy = _LEGACY_SPEC_RE.match(line)
    if legacy:
        raw_name, operator, version = legacy.groups()
        name, _ = strip_pip_extras(raw_name)
        return _requirement_package(name, operator, version, is_direct=is_direct)
    bare = _BARE_NAME_RE.fullmatch(line)
    return _unversioned_package(bare.group(1), is_direct=is_direct) if bare else None


def requirements_file_packages(req_file: Path) -> list[Package]:
    """Declarations of a ``requirements.txt``; unreadable or malformed lines record a coverage gap."""
    packages: list[Package] = []
    malformed = False
    try:
        lines = read_text_limited(req_file).splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("Failed to read requirements.txt at %s: %s", req_file, exc)
        record_manifest_parse_warning(
            ecosystem="pypi",
            path=str(req_file),
            detail="requirements.txt could not be read; Python dependencies were not scanned",
        )
        return packages
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        parsed = requirement_line_package(clean_requirement_line(line), is_direct=True)
        if isinstance(parsed, Package):
            packages.append(_with_manifest_location(parsed, req_file, line_number))
        elif parsed is None:
            malformed = True
    if malformed:
        record_manifest_parse_warning(
            ecosystem="pypi",
            path=str(req_file),
            detail="requirements.txt contains malformed or truncated entries; Python dependency coverage is partial",
        )
    return packages
