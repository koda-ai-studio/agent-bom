"""Canonical go rules for ecosystem version comparison.

Go module versions are SemVer 2.0 with a leading ``v`` (``golang.org/x/mod/semver``):

- ``+incompatible`` (and any other build metadata) is ignored when ordering,
  so ``v2.0.0+incompatible`` is the same release as ``v2.0.0``. PEP 440 would
  read it as a local version that sorts *above* the bare tag, hiding a CVE
  whose range ends at ``2.0.0``.
- A pseudo-version ``vX.Y.Z-0.<ts>-<sha>`` is a pre-release of ``vX.Y.Z``
  whose first identifier is the numeral ``0``, so it sorts below ``rc.1`` of
  the same base; ``vX.Y.Z-rc.1.0.<ts>-<sha>`` sits between ``rc.1`` and
  ``rc.2``. Collapsing a pseudo-version to its base and ordering it above a
  pre-release fix let a module built from an old commit read as patched.
"""

from __future__ import annotations

from agent_bom.core.versions.semver import _compare_strict_semver
from agent_bom.core.versions.validation import _GO_PSEUDO_RE


def _go_pseudo_timestamp(version: str) -> str | None:
    match = _GO_PSEUDO_RE.match(version)
    return match.group(1) if match else None


def _strip_go_build_metadata(version: str) -> str:
    """Drop ``+incompatible`` and other build metadata; Go ignores it when ordering."""
    return version.split("+", 1)[0]


def _go_packaging_operand(version: str) -> str:
    """Return the ``X.Y.Z`` base of a Go version for packaging comparison.

    A pseudo-version (``vX.Y.Z-<ts>-<sha>``) is collapsed to its ``X.Y.Z``
    base so it can be ordered against an ordinary tagged bound; the
    date/sha suffix is not PEP 440-parsable on its own. Plain tags just
    lose the leading ``v``.
    """
    if _go_pseudo_timestamp(version):
        version = version.split("-", 1)[0]
    return version[1:] if version.startswith("v") else version


def _compare_go_versions(left: str, right: str) -> int | None:
    left = _strip_go_build_metadata(left.strip())
    right = _strip_go_build_metadata(right.strip())
    # Go versions are SemVer; the strict comparator orders arbitrary
    # pre-release identifiers exactly as ``semver.Compare`` does, including
    # pseudo-version suffixes: the pre-release lane (``0.`` vs ``rc.1.0.``)
    # decides first and the fixed-width timestamp orders commits within a lane.
    # Only forms it cannot parse (``v1.2``) fall through to packaging.
    semver_cmp = _compare_strict_semver(left, right)
    if semver_cmp is not None:
        return semver_cmp
    left_ts = _go_pseudo_timestamp(left)
    right_ts = _go_pseudo_timestamp(right)
    try:
        from packaging.version import Version

        left_norm = _go_packaging_operand(left)
        right_norm = _go_packaging_operand(right)
        base_cmp = (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
        if base_cmp:
            return base_cmp
        # Same X.Y.Z base and exactly one side is a pseudo-version. A
        # pseudo-version is a pre-release of its base ("compares higher than its
        # base version, but lower than the next tagged version"), so it sorts
        # strictly BELOW the bare tag. Collapsing to equality here would let a
        # pseudo-version read as already past a fix bound.
        if bool(left_ts) != bool(right_ts):
            return -1 if left_ts else 1
        return 0
    except Exception:  # noqa: BLE001
        return None
