"""Version-ordering regressions that turned real CVE matches into ``unaffected``.

Four ecosystems ordered versions against their own specification, and in each
case the installed version sorted *above* the advisory's fixed version, so the
range matcher reported the package as already patched:

* RPM — ``rpmvercmp`` compares ``[epoch:]version`` first and the ``release``
  only on a tie; the comparator ran over the whole ``version-release`` string
  with ``-`` as an ordinary separator, so ``2.4-12.el8`` sorted above the fix
  ``2.4.1-1.el8``.
* Cargo / Pub / Hex / SwiftURL — SemVer 2.0 ecosystems were routed through
  PEP 440, which reads ``1.0.0-test.1`` as a *post*-release of ``1.0.0`` and
  drops the counter in ``canary.1`` vs ``canary.2``.
* Go — ``+incompatible`` is build metadata (ignored by ``semver.Compare``),
  not a PEP 440 local version that sorts above the bare tag; and a
  pseudo-version ``v1.5.0-0.2020…-abc`` is a pre-release whose first
  identifier ``0`` sorts below ``rc.1``.
* PyPI — the ``-dev1`` / ``-post1`` dash spellings left a stray ``-`` behind
  during normalisation, fell into the local-suffix fallback and sorted above
  the bare release.

Every ordering case is asserted in both directions and through
``version_match_state`` at the fix boundary, so removing a false negative
cannot quietly buy a false positive.
"""

from __future__ import annotations

import pytest

from agent_bom.core.versions.osv import version_match_state
from agent_bom.version_utils import compare_version_order


def _assert_ascending(lower: str, higher: str, ecosystem: str) -> None:
    assert compare_version_order(lower, higher, ecosystem) == -1, f"{lower} should sort below {higher} ({ecosystem})"
    assert compare_version_order(higher, lower, ecosystem) == 1, f"{higher} should sort above {lower} ({ecosystem})"


def _assert_equal(left: str, right: str, ecosystem: str) -> None:
    assert compare_version_order(left, right, ecosystem) == 0
    assert compare_version_order(right, left, ecosystem) == 0


# ---------------------------------------------------------------------------
# RPM: version before release
# ---------------------------------------------------------------------------

RPM_ASCENDING = [
    ("2.4-12.el8", "2.4.1-1.el8"),  # version wins over a higher release
    ("1:1.1.1-8.el8", "1:1.1.1k-1.el8"),  # OpenSSL letter suffix is part of the version
    ("3.0.7-24.el9", "3.0.7-25.el9"),  # same version: release decides (already correct)
    ("1.0-1", "1.0^20200101-1"),  # rpm 4.15 caret: post-release of 1.0
    ("1.0~rc1-5", "1.0-1"),  # tilde pre-release sorts below the release regardless of release number
    ("2.4-12.el8", "2.4-12.el8.1"),  # release-only difference still honoured
]


@pytest.mark.parametrize(("lower", "higher"), RPM_ASCENDING)
@pytest.mark.parametrize("ecosystem", ["rpm", "linux", "RPM"])
def test_rpm_orders_version_before_release(lower: str, higher: str, ecosystem: str) -> None:
    _assert_ascending(lower, higher, ecosystem)


def test_rpm_release_only_compared_when_both_sides_carry_one() -> None:
    # A bare upstream version against a packaged one: same version, so the
    # packaged release counts as newer, mirroring rpmvercmp with a missing release.
    _assert_ascending("2.4.1", "2.4.1-1.el8", "rpm")
    _assert_equal("2.4.1-1.el8", "2.4.1-1.el8", "rpm")


def test_rpm_false_negative_at_the_fix_boundary() -> None:
    assert version_match_state("2.4-12.el8", "0", "2.4.1-1.el8", None, "Red Hat:enterprise_linux:8") == "affected"
    assert version_match_state("2.4.1-1.el8", "0", "2.4.1-1.el8", None, "Red Hat:enterprise_linux:8") == "unaffected"
    assert version_match_state("1:1.1.1-8.el8", "0", "1:1.1.1k-1.el8", None, "rpm") == "affected"


# ---------------------------------------------------------------------------
# SemVer ecosystems that are not npm
# ---------------------------------------------------------------------------

SEMVER_ECOSYSTEMS = ["crates.io", "cargo", "Pub", "pub", "Hex", "hex", "SwiftURL", "swift"]

SEMVER_ASCENDING = [
    ("1.0.0-test.1", "1.0.0"),  # any pre-release sorts below the release
    ("1.0.0-canary.1", "1.0.0-canary.2"),  # the counter is significant
    ("1.0.0-nightly.3", "1.0.0-nightly.10"),  # numeric identifiers compare numerically
    ("0.12.0-alpha.1", "0.12.0-alpha.beta"),  # numeric identifier < alphanumeric one
    ("1.0.0-alpha", "1.0.0-alpha.1"),  # fewer identifiers sort first
    ("1.0.0-rc.1", "1.0.0"),
    ("1.0.0", "1.0.1-alpha.1"),
]


@pytest.mark.parametrize(("lower", "higher"), SEMVER_ASCENDING)
@pytest.mark.parametrize("ecosystem", SEMVER_ECOSYSTEMS)
def test_semver_ecosystems_use_semver_precedence(lower: str, higher: str, ecosystem: str) -> None:
    _assert_ascending(lower, higher, ecosystem)


@pytest.mark.parametrize("ecosystem", SEMVER_ECOSYSTEMS)
def test_semver_build_metadata_is_ignored(ecosystem: str) -> None:
    _assert_equal("1.0.0+build.7", "1.0.0", ecosystem)


def test_cargo_false_negative_at_the_fix_boundary() -> None:
    assert version_match_state("1.0.0-test.1", "0", "1.0.0", None, "crates.io") == "affected"
    assert version_match_state("1.0.0-canary.1", "0", "1.0.0-canary.2", None, "crates.io") == "affected"
    assert version_match_state("1.0.0-canary.2", "0", "1.0.0-canary.2", None, "crates.io") == "unaffected"
    assert version_match_state("1.0.0", "0", "1.0.0", None, "crates.io") == "unaffected"


def test_npm_ordering_is_unchanged_by_the_wider_routing() -> None:
    _assert_ascending("13.4.20-canary.13", "13.4.20", "npm")
    _assert_ascending("1.0.0-canary.1", "1.0.0-canary.2", "npm")


def test_pypi_keeps_pep440_post_release_semantics() -> None:
    # ``1.0.0-foo`` really is a post-release on PyPI; the SemVer routing must not
    # leak into Python packages.
    assert compare_version_order("1.0.0-1", "1.0.0", "pypi") == 1


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------

GO_ASCENDING = [
    ("v1.5.0-0.20200101000000-abcdefabcdef", "v1.5.0-rc.1"),  # pseudo-version precedes an rc of the same base
    ("v1.5.0-rc.1.0.20200101000000-abcdefabcdef", "v1.5.0-rc.2"),  # pseudo on rc.1 precedes rc.2
    ("v1.5.0-rc.1", "v1.5.0-rc.1.0.20200101000000-abcdefabcdef"),  # ...but follows rc.1 itself
    ("v1.0.0-test", "v1.0.0"),  # arbitrary prerelease identifier
    ("v1.0.0-alpha.1", "v1.0.0-alpha.beta"),
    ("v1.0.0-0.20200101000000-abcdefabcdef", "v1.0.0"),  # pseudo-version precedes its base tag (already correct)
    # Two pseudo-versions of one base: the pre-release prefix decides before the
    # timestamp, so a newer commit on the ``0.`` lane still sorts below an ``rc.1`` lane.
    ("v1.5.0-0.20200102000000-abcdefabcdef", "v1.5.0-rc.1.0.20200101000000-abcdefabcdef"),
    ("v1.5.0-0.20200101000000-abcdefabcdef", "v1.5.0-0.20200102000000-abcdefabcdef"),  # same lane: timestamp decides
]


@pytest.mark.parametrize(("lower", "higher"), GO_ASCENDING)
def test_go_prerelease_and_pseudo_version_precedence(lower: str, higher: str) -> None:
    _assert_ascending(lower, higher, "go")


def test_go_incompatible_is_build_metadata() -> None:
    _assert_equal("v2.0.0+incompatible", "v2.0.0", "go")
    _assert_ascending("v2.0.0+incompatible", "v2.0.1", "go")
    _assert_ascending("v1.9.9", "v2.0.0+incompatible", "go")


def test_go_false_negative_at_the_fix_boundary() -> None:
    assert version_match_state("v2.0.0+incompatible", "0", None, "2.0.0", "Go") == "affected"
    assert version_match_state("v2.0.0+incompatible", "0", "2.0.0", None, "Go") == "unaffected"
    assert version_match_state("v1.5.0-0.20200101000000-abcdefabcdef", "0", "1.5.0-rc.1", None, "Go") == "affected"


# ---------------------------------------------------------------------------
# PyPI dash-separated dev / post releases
# ---------------------------------------------------------------------------

PYPI_ASCENDING = [
    ("4.2.0-dev1", "4.2.0"),
    ("4.2.0.dev1", "4.2.0-dev2"),  # dot and dash spellings order together
    ("1.0-post1", "1.0-post2"),
    ("1.0", "1.0-post1"),
    ("1.0+abc", "1.0+r1"),  # local labels compare as-is; ``r1`` is not rewritten to ``.post1``
]


@pytest.mark.parametrize(("lower", "higher"), PYPI_ASCENDING)
def test_pypi_dash_forms_follow_pep440(lower: str, higher: str) -> None:
    _assert_ascending(lower, higher, "pypi")


def test_pypi_false_negative_at_the_fix_boundary() -> None:
    assert version_match_state("4.2.0-dev1", "0", "4.2.0", None, "PyPI") == "affected"
    assert version_match_state("4.2.0", "0", "4.2.0", None, "PyPI") == "unaffected"
