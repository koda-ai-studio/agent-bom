"""Sync and async retry clients share bounded upstream timing semantics."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from agent_bom import http_client


@pytest.mark.parametrize("header", ["NaN", "Infinity", "-Infinity", "1e999", "invalid"])
@pytest.mark.asyncio
async def test_retry_clients_use_finite_backoff_for_invalid_upstream_delay(monkeypatch, header):
    monkeypatch.setattr("agent_bom.security.validate_url", lambda _url: None)
    monkeypatch.setattr(http_client.random, "uniform", lambda *_: 0)
    sleep_async, sleep_sync = AsyncMock(), MagicMock()
    monkeypatch.setattr(http_client.asyncio, "sleep", sleep_async)
    monkeypatch.setattr(http_client.time, "sleep", sleep_sync)
    response = httpx.Response(503, headers={"Retry-After": header})
    success = httpx.Response(200)
    async_client = AsyncMock()
    async_client.request.side_effect = [response, success]
    sync_client = MagicMock()
    sync_client.request.side_effect = [response, success]

    assert await http_client.request_with_retry(async_client, "GET", "https://example.com", max_retries=1) is success
    assert http_client.sync_request_with_retry(sync_client, "GET", "https://example.com", max_retries=1) is success
    sleep_async.assert_awaited_once_with(http_client.INITIAL_BACKOFF)
    sleep_sync.assert_called_once_with(http_client.INITIAL_BACKOFF)


@pytest.mark.parametrize("header,expected", [("Thu, 01 Jan 1970 00:03:20 GMT", 100), ("0.25", 0.25), ("-1", 0), ("0", 0)])
def test_retry_client_honors_valid_dates_and_delta_seconds(monkeypatch, header, expected):
    monkeypatch.setattr(http_client.time, "time", lambda: 100)
    response = httpx.Response(503, headers={"Retry-After": header})
    assert http_client._retry_after_wait(response, 1) == min(expected, http_client.MAX_BACKOFF)
