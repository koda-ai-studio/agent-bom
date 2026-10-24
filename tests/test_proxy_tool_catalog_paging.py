"""Paginated tools/list responses must be judged as one catalog, not per page."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from agent_bom import proxy
from agent_bom.runtime.detectors import ToolDriftDetector
from agent_bom.runtime.mcp_protocol import MAX_TOOL_CATALOG_PAGES
from agent_bom.runtime.proxy_relay import ServerMessage, gate_client_message, track_declared_tools
from agent_bom.runtime.proxy_session import ProxySession


def _session() -> tuple[ProxySession, list]:
    alerts: list = []
    session = ProxySession(
        host=proxy,
        policy={},
        log_file=None,
        metrics=SimpleNamespace(total_messages_client_to_server=0),
        detectors=SimpleNamespace(drift=ToolDriftDetector()),
        scan_config=None,
        options=None,
        control=None,
        audit=None,
    )

    async def _capture(found, _log=None):
        alerts.extend(found)

    session.handle_alerts = _capture  # type: ignore[method-assign]
    return session, alerts


def _page(names: list[str], cursor: object = None, request_id: int = 1) -> ServerMessage:
    result: dict = {"tools": [{"name": n} for n in names]}
    if cursor is not None:
        result["nextCursor"] = cursor
    return ServerMessage(msg={"jsonrpc": "2.0", "id": request_id, "result": result}, line=b"")


def _feed(session: ProxySession, *pages: ServerMessage) -> None:
    for page in pages:
        asyncio.run(track_declared_tools(session, page))


def _request(session: ProxySession, request_id: int, cursor: str | None = None) -> None:
    params = {"cursor": cursor} if cursor is not None else {}
    msg = {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params}
    asyncio.run(gate_client_message(session, msg, {}))


def test_two_page_catalog_is_one_baseline_with_no_drift():
    session, alerts = _session()
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c"]))
    assert alerts == []
    assert session.detectors.drift.baseline == {"a", "b", "c"}
    assert session.declared_tools == {"a", "b", "c"}


def test_three_page_catalog_relisted_raises_no_drift():
    session, alerts = _session()
    listing = (_page(["a"], cursor="p2"), _page(["b"], cursor="p3"), _page(["c", "d"]))
    _feed(session, *listing)
    _feed(session, *listing)
    assert alerts == []
    assert session.detectors.drift.baseline == {"a", "b", "c", "d"}


def test_genuinely_new_tool_on_later_full_listing_still_alerts():
    session, alerts = _session()
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c"]))
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c", "exfiltrate"]))
    assert [a.message for a in alerts] == ["New tools detected after startup: exfiltrate"]


def test_genuine_removal_on_later_full_listing_still_alerts():
    session, alerts = _session()
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c"]))
    _feed(session, _page(["a"], cursor="p2"), _page(["c"]))
    assert [a.message for a in alerts] == ["Tools removed after startup: b"]


def test_page_cap_hit_never_reports_removed_tools():
    session, alerts = _session()
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c"]))
    capped = [_page([f"t{i}"], cursor=f"c{i}") for i in range(MAX_TOOL_CATALOG_PAGES + 3)]
    _feed(session, *capped, _page(["tail"]))
    assert all("removed" not in a.message for a in alerts)
    assert session.detectors.drift.baseline == {"a", "b", "c"}


def test_capped_first_catalog_does_not_become_the_baseline():
    session, alerts = _session()
    capped = [_page([f"t{i}"], cursor=f"c{i}") for i in range(MAX_TOOL_CATALOG_PAGES + 1)]
    _feed(session, *capped, _page(["tail"]))
    assert alerts == []
    assert session.detectors.drift.baseline is None
    _feed(session, _page(["a"], cursor="p2"), _page(["b"]))
    assert alerts == []
    assert session.detectors.drift.baseline == {"a", "b"}


def test_repeated_cursor_marks_catalog_incomplete_without_removed_alert():
    session, alerts = _session()
    _feed(session, _page(["a", "b"], cursor="p2"), _page(["c"]))
    _feed(session, _page(["a"], cursor="loop"), _page(["x"], cursor="loop"), _page(["z"]))
    assert all("removed" not in a.message for a in alerts)


def test_incomplete_catalog_still_reports_present_new_tools():
    session, alerts = _session()
    _feed(session, _page(["a"], cursor="p2"), _page(["b"]))
    capped = [_page(["a", "rogue"] if i == 0 else [f"t{i}"], cursor=f"c{i}") for i in range(MAX_TOOL_CATALOG_PAGES + 1)]
    _feed(session, *capped)
    messages = [a.message for a in alerts]
    assert any("rogue" in m and m.startswith("New tools") for m in messages)
    assert all("removed" not in m for m in messages)


def test_restarted_listing_discards_abandoned_partial_pages():
    session, alerts = _session()
    _request(session, 1)
    _feed(session, _page(["a", "b"], cursor="p2", request_id=1))
    _request(session, 2, cursor="p2")
    _feed(session, _page(["c"], request_id=2))
    _request(session, 3)
    _feed(session, _page(["a", "ghost"], cursor="p2", request_id=3))
    _request(session, 4)
    _feed(session, _page(["a", "b"], cursor="p2", request_id=4))
    _request(session, 5, cursor="p2")
    _feed(session, _page(["c"], request_id=5))
    assert alerts == []


def test_single_page_catalog_behaviour_is_unchanged():
    session, alerts = _session()
    _feed(session, _page(["a", "b"]))
    _feed(session, _page(["a", "b", "c"]))
    assert [a.message for a in alerts] == ["New tools detected after startup: c"]


# ── SSE proxy: the declared catalog spans every tools/list page ──


def _pages(*pages: tuple[list[str], object]) -> list[dict]:
    return [{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": n} for n in names], "nextCursor": cursor}} for names, cursor in pages]


@pytest.mark.asyncio
async def test_fetch_tool_catalog_follows_every_page():
    from agent_bom.runtime.tool_catalog_pages import fetch_tool_catalog

    responses = iter(_pages((["a", "b"], "p2"), (["c"], "p3"), (["d"], None)))
    seen_cursors: list[object] = []

    async def fetch(cursor):
        seen_cursors.append(cursor)
        return next(responses)

    catalog = await fetch_tool_catalog(fetch)
    assert catalog.names == ["a", "b", "c", "d"]
    assert catalog.complete is True
    assert seen_cursors == [None, "p2", "p3"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pages",
    [
        _pages((["a"], "same"), (["b"], "same"), (["c"], None)),
        _pages((["a"], 7)),
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "a"}], "nextCursor": "p2"}},
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -1}},
        ],
    ],
    ids=["repeated-cursor", "non-string-cursor", "error-page"],
)
async def test_fetch_tool_catalog_reports_incomplete_listing(pages):
    from agent_bom.runtime.tool_catalog_pages import fetch_tool_catalog

    responses = iter(pages)

    async def fetch(cursor):
        return next(responses)

    catalog = await fetch_tool_catalog(fetch)
    assert catalog.complete is False
    assert "a" in catalog.names


@pytest.mark.asyncio
async def test_fetch_tool_catalog_stops_at_the_page_cap():
    from agent_bom.runtime.mcp_protocol import MAX_TOOL_CATALOG_PAGES
    from agent_bom.runtime.tool_catalog_pages import fetch_tool_catalog

    calls = 0

    async def fetch(cursor):
        nonlocal calls
        calls += 1
        return _pages(([f"t{calls}"], f"p{calls}"))[0]

    catalog = await fetch_tool_catalog(fetch)
    assert calls == MAX_TOOL_CATALOG_PAGES
    assert catalog.complete is False


@pytest.mark.asyncio
async def test_sse_proxy_does_not_block_a_tool_declared_on_a_later_page(monkeypatch):
    import io
    import json
    from unittest.mock import AsyncMock, MagicMock

    from agent_bom import proxy

    listing = iter(_pages((["first"], "p2"), (["second"], None)))
    posted: list[tuple[str, dict]] = []

    async def post(url, **kwargs):
        sent = kwargs.get("json")
        if sent is None:
            sent = json.loads(kwargs.get("content") or b"{}")
        posted.append((url, sent))
        reply = {"jsonrpc": "2.0", "id": sent.get("id"), "result": {"content": []}}
        body = next(listing) if sent.get("method") == "tools/list" else reply
        response = MagicMock()
        response.json.return_value = body
        response.raise_for_status.return_value = None
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        return response

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.side_effect = post
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    call = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "second", "arguments": {}}}
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[json.dumps(call).encode() + b"\n", b""]))
    stdout = io.BytesIO()
    monkeypatch.setattr(proxy.sys, "stdout", type("Stdout", (), {"buffer": stdout})())

    assert await proxy._proxy_sse_server(url="https://fixture.example", block_undeclared=True) == 0

    listing_cursors = [body.get("params", {}).get("cursor") for _url, body in posted if body.get("method") == "tools/list"]
    assert listing_cursors == [None, "p2"]
    assert any(body.get("method") == "tools/call" for _url, body in posted), "a tool declared on page 2 must be forwarded"
    assert b"undeclared" not in stdout.getvalue().lower()
