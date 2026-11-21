"""Runs inside tests/test_ci_selection_plugin.py's selected pytest runs (and on its own)."""

from __future__ import annotations

import os


def test_tests_never_inherit_the_selection() -> None:
    """A test that starts its own pytest must not be filtered by the shard's selection."""
    assert "AGENT_BOM_PYTEST_SELECTION" not in os.environ
