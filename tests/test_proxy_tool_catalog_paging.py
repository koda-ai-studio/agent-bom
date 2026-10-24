"""Paginated tools/list responses must be judged as one catalog, not per page."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

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
