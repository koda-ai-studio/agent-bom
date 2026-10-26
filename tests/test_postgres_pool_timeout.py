"""A request never waits psycopg_pool's 30 s default for a connection: the pool wait is bounded and configurable."""

from __future__ import annotations

import sys
import types

from agent_bom import config
from agent_bom.api import postgres_common


def test_application_pool_bounds_the_connection_wait(monkeypatch) -> None:
    captured: dict = {}

    class FakePool:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=FakePool))
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent:pw@localhost/test")
    postgres_common._new_application_pool(min_size=1, max_size=2)

    assert captured["timeout"] == config.POSTGRES_POOL_TIMEOUT_SECONDS == 10.0
