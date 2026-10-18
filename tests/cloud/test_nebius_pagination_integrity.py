"""Incomplete provider pages must not masquerade as complete inventory."""

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.nebius import _discover_gpu_instances, _nebius_get_all


def _response(payload):
    response = MagicMock()
    response.json.return_value = payload
    return response


@pytest.mark.parametrize(
    "payload",
    [[], {}, {"instances": None}, {"instances": "bad"}, {"instances": ["bad"]}],
)
def test_malformed_page_is_not_empty_success(payload):
    with patch("agent_bom.http_client.sync_request_with_retry", return_value=_response(payload)):
        with pytest.raises(CloudDiscoveryError, match="invalid.*page"):
            _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances")


@pytest.mark.parametrize("cursor", [False, 7, ["opaque"], {"token": "opaque"}])
def test_invalid_cursor_is_not_end_of_inventory(cursor):
    with patch(
        "agent_bom.http_client.sync_request_with_retry",
        return_value=_response({"instances": [], "nextPageToken": cursor}),
    ):
        with pytest.raises(CloudDiscoveryError, match="invalid.*cursor"):
            _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances")


def test_repeated_cursor_fails_without_disclosing_cursor():
    with patch(
        "agent_bom.http_client.sync_request_with_retry",
        return_value=_response({"instances": [{"id": "one"}], "nextPageToken": "private-cursor"}),
    ) as request:
        with pytest.raises(CloudDiscoveryError, match="repeated.*cursor") as error:
            _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances")
        assert request.call_count == 2
        assert "private-cursor" not in str(error.value)


def test_page_limit_does_not_return_truncated_inventory():
    pages = [_response({"instances": [{"id": str(i)}], "nextPageToken": str(i + 1)}) for i in range(50)]
    with patch("agent_bom.http_client.sync_request_with_retry", side_effect=pages) as request:
        with pytest.raises(CloudDiscoveryError, match="page limit"):
            _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances")
        assert request.call_count == 50


def test_terminal_page_at_limit_is_complete():
    pages = [_response({"instances": [{"id": str(i)}], "nextPageToken": str(i + 1)}) for i in range(49)]
    pages.append(_response({"instances": [{"id": "last"}], "nextPageToken": None}))
    with patch("agent_bom.http_client.sync_request_with_retry", side_effect=pages):
        items = _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances")
    assert len(items) == 50
    assert items[-1] == {"id": "last"}


def test_complete_pages_preserve_items_and_caller_parameters():
    params = {"project_id": "scope"}
    calls = []

    def request(*args, **kwargs):
        calls.append(dict(kwargs["params"]))
        return _response(
            {"instances": [{"id": "one"}], "nextPageToken": "next"} if len(calls) == 1 else {"data": [{"id": "two"}], "next_page_token": ""}
        )

    with patch("agent_bom.http_client.sync_request_with_retry", side_effect=request):
        items = _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances", params)
    assert items == [{"id": "one"}, {"id": "two"}]
    assert calls == [{"project_id": "scope"}, {"project_id": "scope", "pageToken": "next"}]
    assert params == {"project_id": "scope"}


def test_malformed_inventory_reaches_discovery_warning():
    with patch("agent_bom.http_client.sync_request_with_retry", return_value=_response({"unexpected": []})):
        agents, warnings = _discover_gpu_instances("fixture-key", "fixture-project")
    assert not agents
    assert len(warnings) == 1
    assert "invalid" in warnings[0]
