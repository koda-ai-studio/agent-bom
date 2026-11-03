"""Classify repository paths that hold documentation, examples or tests.

A hardcoded password in ``docs/`` or a shell sink in ``examples/gulpfile.js`` is
usually illustrative. Findings there are kept and labelled, but lowered to
``low`` so the default ``--fail-on-severity`` gate (``high``) is not tripped by
sample code. ``--fail-on-severity low`` still gates them. Documented in
``site-docs/reference/exit-codes.md``.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

PathContext = Literal["documentation", "example", "test"]

CONTEXT_SEVERITY = "low"

_DOC_DIRS = frozenset({"docs", "doc", "documentation", "site-docs", "docs-site"})
_DOC_SUFFIXES = frozenset({".md", ".mdx", ".markdown", ".rst", ".adoc"})
_DOC_STEMS = ("readme", "changelog", "contributing")
_EXAMPLE_DIRS = frozenset({"examples", "example", "samples", "sample"})
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "testing", "testdata", "fixtures", "__fixtures__", "__mocks__", "spec", "specs"})
_TEST_INFIXES = (".test.", ".spec.")
_TEST_SUFFIXES = ("_test.py", "_test.go", "_test.rb", "_spec.rb")


def classify_path_context(path: str) -> PathContext | None:
    """Return the lower-confidence context of a repository-relative *path*, if any.

    Directory names win over the file name, so ``examples/README.md`` is an
    example and ``docs/conftest.py`` is documentation.
    """
    if not path:
        return None
    parts = [part.lower() for part in PurePosixPath(path.replace("\\", "/")).parts]
    if not parts:
        return None
    for part in parts[:-1]:
        if part in _DOC_DIRS:
            return "documentation"
        if part in _EXAMPLE_DIRS:
            return "example"
        if part in _TEST_DIRS:
            return "test"
    name = parts[-1]
    if name.startswith("test_") or name.endswith(_TEST_SUFFIXES) or any(infix in name for infix in _TEST_INFIXES):
        return "test"
    if PurePosixPath(name).suffix in _DOC_SUFFIXES or name.startswith(_DOC_STEMS):
        return "documentation"
    return None


def context_downgrade_reason(context: PathContext) -> str:
    """Human-readable reason recorded on a finding lowered for its path context."""
    return f"{context} path; illustrative code is lower-confidence and non-gating at the default threshold"
