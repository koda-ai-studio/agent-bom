"""Malformed model records must not suppress independent AI Studio inventory."""

import httpx
import pytest

from agent_bom.cloud import nebius


@pytest.mark.parametrize("name", [None, [], {"private-marker": "invalid"}])
@pytest.mark.parametrize("position", [0, 1])
def test_invalid_model_name_retains_valid_neighbors(monkeypatch, name, position):
    records = [{"id": "first", "name": "first", "version": "1"}, {"id": "last", "name": "last", "version": "2"}]
    records.insert(position, {"id": "private-marker", "name": name})
    response = httpx.Response(200, json={"models": records}, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)
    agents, warnings = nebius._discover_ai_studio("fixture", "fixture-project")
    assert [a.name for a in agents] == ["nebius-ai-studio:first", "nebius-ai-studio:last"]
    assert [a.mcp_servers[0].packages[0].version for a in agents] == ["1", "2"]
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:ai-studio:unavailable:")
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


@pytest.mark.parametrize("models", [[], [{"id": "fallback"}], [{"id": "named", "name": "named"}]])
def test_valid_models_remain_complete(monkeypatch, models):
    response = httpx.Response(200, json={"models": models}, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(nebius.http_client, "sync_request_with_retry", lambda *a, **kw: response)
    agents, warnings = nebius._discover_ai_studio("fixture", "fixture-project")
    assert [a.name for a in agents] == [f"nebius-ai-studio:{m['id']}" for m in models]
    assert warnings == []
