"""Restore tenant environment variables after every test.

``cli/_profiles.apply_profile_environment`` deliberately writes the profile's
tenant into ``os.environ`` for the CLI process. Under pytest every CliRunner
call shares one process, so without this guard a profile test leaks
``AGENT_BOM_TENANT_ID`` into later tests and silently changes their tenant.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

_TENANT_VARS = ("AGENT_BOM_TENANT_ID", "AGENT_BOM_MCP_TENANT_ID")


@pytest.fixture(autouse=True)
def _restore_tenant_environment() -> Iterator[None]:
    saved = {name: os.environ.get(name) for name in _TENANT_VARS}
    yield
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
