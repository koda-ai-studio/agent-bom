"""Authorization seam for orchestration tests; real grants have separate tests."""

import pytest


@pytest.fixture(autouse=True)
def authorized_side_scan_orchestration(monkeypatch):
    """Keep executor/state tests independent of credential construction."""
    from agent_bom.api import side_scan_authorization, side_scan_scheduler

    monkeypatch.setattr(side_scan_authorization, "authorize_side_scan", lambda **kwargs: {})
    monkeypatch.setattr(side_scan_scheduler, "authorize_side_scan", lambda **kwargs: {})
