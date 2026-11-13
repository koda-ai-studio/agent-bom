"""A push the control plane refuses for auth names the fix (dev key, --push-api-key / env var) without the key."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.cli.agents._post import _push_report


def _client(status: int) -> AsyncMock:
    resp = AsyncMock()
    resp.status_code = status
    resp.text = '{"detail":"Unauthorized"}'
    resp.headers = {}
    client = AsyncMock()
    client.post = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _push(status: int, api_key: str | None, capsys) -> str:
    ctx = SimpleNamespace(con=None, target_scope=None)
    with (
        patch("agent_bom.http_client.create_client", return_value=_client(status)),
        patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
        patch("agent_bom.cli.agents._post.to_json", return_value={"agents": []}),
    ):
        delivered = _push_report(ctx, object(), "http://127.0.0.1:8422", api_key, quiet=True)
    assert delivered is False
    return capsys.readouterr().err


@pytest.mark.parametrize("status", [401, 403])
def test_missing_key_points_at_the_dev_key_and_both_ways_to_pass_it(status: int, capsys) -> None:
    err = _push(status, None, capsys)

    assert f"HTTP {status}" in err
    assert "--push-api-key" in err
    assert "AGENT_BOM_PUSH_API_KEY" in err
    assert "Dev API key" in err


def test_rejected_key_is_named_but_never_printed(capsys) -> None:
    err = _push(401, "abk_secret_dev_key_value", capsys)

    assert "rejected" in err
    assert "--push-api-key" in err
    assert "abk_secret_dev_key_value" not in err
