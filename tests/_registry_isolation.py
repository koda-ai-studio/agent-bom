"""Keep ``agent-bom check`` off the package registries during the suite.

The CLI confirms an advisory-free pin is published before calling it clean.
Without this, every clean ``check`` test would query PyPI or npm. The lookup
fails open, so the suite would pass offline but slowly and nondeterministically.
Tests of the existence check patch ``version_published`` themselves, which
overrides this.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _registry_versions_published():
    import agent_bom.cli._check_published as check_published

    async def _published(*_args, **_kwargs):
        return True

    original = check_published.version_published
    check_published.version_published = _published
    try:
        yield
    finally:
        check_published.version_published = original
