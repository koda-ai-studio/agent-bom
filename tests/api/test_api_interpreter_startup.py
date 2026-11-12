"""API start-up keeps its own objects out of later full garbage collections.

A full collection stops every thread, the event loop included, for as long as
it takes to walk every tracked object. Start-up freezes the objects that exist
once the API is up (imports, routes, schemas) so later full collections skip
them; ``/health`` p99 during a 500-agent push fell from about 340 ms to under
the 250 ms budget.
"""

from __future__ import annotations

import gc

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import server_storage


@pytest.fixture
def unfrozen_heap(monkeypatch):
    gc.unfreeze()
    monkeypatch.setattr(server_storage, "_startup_heap_frozen", False)
    yield
    gc.unfreeze()


def test_startup_moves_existing_objects_out_of_later_collections(unfrozen_heap):
    assert gc.get_freeze_count() == 0
    server_storage._freeze_startup_heap()
    assert gc.get_freeze_count() > 0
    assert gc.get_count()[2] == 0


def test_the_heap_is_frozen_once_per_process(unfrozen_heap):
    server_storage._freeze_startup_heap()
    frozen = gc.get_freeze_count()
    survivors = [[index] for index in range(1000)]
    server_storage._freeze_startup_heap()
    assert gc.get_freeze_count() == frozen
    del survivors


def test_api_lifespan_freezes_the_startup_heap(unfrozen_heap):
    from agent_bom.api.server import app

    with TestClient(app):
        assert gc.get_freeze_count() > 0
