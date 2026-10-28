"""Authorization seam for orchestration tests; real grants have separate tests."""

import pytest


@pytest.fixture(autouse=True)
def authorized_side_scan_orchestration(monkeypatch):
    """Keep executor/state tests independent of credential construction."""
    from agent_bom.api import side_scan_authorization, side_scan_scheduler

    def fixture_client_factory(provider, *, account_id, region):
        # Resolved at call time so a test's monkeypatch of the SDK builder is honoured;
        # the executor itself never falls back to ambient credentials without a factory.
        from agent_bom.cloud import side_scan_targets

        return side_scan_targets._default_provider_clients(provider, account_id=account_id, region=region)

    def authorized(**kwargs):
        return {"client_factory": fixture_client_factory, "authorization_ref": "fixture-connection:test"}

    monkeypatch.setattr(side_scan_authorization, "authorize_side_scan", authorized)
    monkeypatch.setattr(side_scan_scheduler, "authorize_side_scan", authorized)
