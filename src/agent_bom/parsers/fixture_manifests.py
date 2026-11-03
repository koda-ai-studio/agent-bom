"""Which project-scan directories hold test fixtures or scaffold templates.

A locked project's resolved dependency set lives in its lockfile. Manifests
under its test-fixture or scaffold-template directories (``tests/fixtures``,
``__fixtures__``, ``templates/``, ``template-*``) are inputs for the project's
own tests or for projects it generates; they are never installed with it.
Scanning them adds declaration-only packages whose versions can only be
guessed from a registry, so a locked project skips them and records a
``fixture_manifest`` scope receipt naming the skipped paths.

A fixture or template directory that carries its own lockfile is treated as
its own project and still scanned: its pinned versions are real evidence and
skipping them could hide a vendored, separately shipped app. A scan rooted
inside a fixture directory scans it, because the caller named it explicitly.
``AGENT_BOM_SCAN_FIXTURE_MANIFESTS=1`` restores scanning of every manifest.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from pathlib import Path

from agent_bom.core.settings import env_flag

INCLUDE_ENV = "AGENT_BOM_SCAN_FIXTURE_MANIFESTS"
FIXTURE_MANIFEST_REASON = "fixture_manifest"
FIXTURE_MANIFEST_DETAIL = (
    f"Test-fixture and scaffold-template manifests inside a locked project were not inventoried; set {INCLUDE_ENV}=1 to include them."
)

_TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec", "specs", "testdata"})
_FIXTURE_DIR_NAMES = frozenset({"fixtures", "fixture"})


def include_fixture_manifests() -> bool:
    return env_flag(INCLUDE_ENV)


def is_fixture_or_template_dir(rel_parts: Sequence[str]) -> bool:
    """True when a directory path relative to the scan root is a fixture or template tree."""
    inside_test_dir = False
    for part in rel_parts:
        lowered = part.lower()
        if lowered == "__fixtures__" or lowered == "templates" or lowered.startswith("template-"):
            return True
        if inside_test_dir and lowered in _FIXTURE_DIR_NAMES:
            return True
        if lowered in _TEST_DIR_NAMES:
            inside_test_dir = True
    return False


def skips_fixture_manifests(rel_parts: Sequence[str], *, ancestor_locked: bool, own_lock: bool) -> bool:
    """A fixture/template directory without its own lockfile, inside a locked project."""
    return ancestor_locked and not own_lock and is_fixture_or_template_dir(rel_parts) and not include_fixture_manifests()


def fixture_skip_warning(rel_paths: Sequence[str], *, limit: int = 8) -> str:
    """One console line naming the skipped directories, relative to the scan root."""
    shown = ", ".join(sorted(rel_paths)[:limit])
    more = f" (+{len(rel_paths) - limit} more)" if len(rel_paths) > limit else ""
    noun = "directory" if len(rel_paths) == 1 else "directories"
    return (
        f"skipped {len(rel_paths)} test-fixture/template manifest {noun} inside a locked project: "
        f"{shown}{more}; set {INCLUDE_ENV}=1 to include them"
    )


class FixtureManifestScope:
    """Per-walk state: which directories inherit a lockfile and which were skipped."""

    def __init__(self, root: Path, report_gap: Callable[..., None], lockfile_names: Collection[str]) -> None:
        self._root = root
        self._report_gap = report_gap
        self._lockfile_names = lockfile_names
        self.skipped: list[str] = []

    def visit(self, directory: Path, ancestor_locked: bool, has_manifest: bool) -> tuple[bool, bool]:
        """Return (parse this directory's manifests, children are inside a locked project)."""
        own_lock = any((directory / name).exists() for name in self._lockfile_names)
        if has_manifest:
            rel_parts = directory.relative_to(self._root).parts
            if skips_fixture_manifests(rel_parts, ancestor_locked=ancestor_locked, own_lock=own_lock):
                self._report_gap(FIXTURE_MANIFEST_REASON, FIXTURE_MANIFEST_DETAIL, directory)
                self.skipped.append("/".join(rel_parts))
                has_manifest = False
        return has_manifest, ancestor_locked or own_lock

    def finish(self, warn: Callable[[str], None]) -> None:
        if self.skipped:
            warn(fixture_skip_warning(self.skipped))
