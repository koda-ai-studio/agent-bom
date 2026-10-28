"""Exercise Snowflake fixtures after a parent-package alias becomes stale."""

import importlib
import types

import pytest


@pytest.fixture(autouse=True, params=["canonical", "stale"])
def _snowflake_facade_alias(request, monkeypatch):
    if request.param == "canonical":
        return
    import agent_bom.cloud as cloud

    canonical = importlib.import_module("agent_bom.cloud.snowflake")
    stale = types.ModuleType(canonical.__name__)
    stale.__dict__.update(canonical.__dict__)
    # patch.dict(sys.modules) can restore the registry without restoring this
    # parent attribute. Discovery resolves the registry, not the old alias.
    monkeypatch.setattr(cloud, "snowflake", stale)
    # Never allow a missed fixture patch to reach the SDK or the network.
    monkeypatch.setattr(canonical, "_get_connection", lambda *args, **kwargs: None)
