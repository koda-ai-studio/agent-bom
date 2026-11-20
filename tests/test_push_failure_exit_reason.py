"""A push the control plane refuses is the named exit reason, not a pointer at a report that never mentions it."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent_bom.cli.agents._post import _push_report
from agent_bom.cli.agents.scan_pipeline.quiet_summary import quiet_verdict


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


def test_failed_push_is_the_quiet_summary_exit_reason(capsys) -> None:
    ctx = SimpleNamespace(con=None, target_scope=None, exit_reasons=[])
    with (
        patch("agent_bom.http_client.create_client", return_value=_client(401)),
        patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
        patch("agent_bom.cli.agents._post.to_json", return_value={"agents": []}),
    ):
        assert _push_report(ctx, object(), "http://127.0.0.1:8422", None, quiet=True) is False

    assert "HTTP 401" in capsys.readouterr().err
    assert len(ctx.exit_reasons) == 1
    assert "not delivered to http://127.0.0.1:8422" in ctx.exit_reasons[0]

    opts = SimpleNamespace(output=None, output_format="console")
    verdict = quiet_verdict(opts, SimpleNamespace(report=None, ctx=ctx, total_packages=0), 1)  # type: ignore[arg-type]
    assert verdict["reasons"] == ctx.exit_reasons
    assert "see the report's scan_run and findings" not in verdict["reasons"]
