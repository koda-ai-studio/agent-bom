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
    [[], {"instances": None}, {"instances": "bad"}, {"instances": ["bad"]}],
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


@pytest.mark.parametrize("payload", [{}, {"nextPageToken": ""}, {"items": []}, {"items": [{"id": "one"}]}])
def test_proto_list_items_and_omitted_empty_field(payload):
    with patch("agent_bom.http_client.sync_request_with_retry", return_value=_response(payload)):
        assert _nebius_get_all("https://example.invalid/instances", "fixture-key", "instances") == payload.get("items", [])


def test_nebius_incomplete_discovery_has_structured_scan_scope():
    from types import SimpleNamespace

    from agent_bom.cli.agents.scan_pipeline.report import _collect_cloud_scopes

    state = SimpleNamespace(
        ctx=SimpleNamespace(
            cloud_provider_successes=[{"provider": "nebius", "item_count": 2}],
            cloud_provider_warnings=[{"provider": "nebius", "warning": "pagination failed"}],
            cloud_provider_failures=[],
        )
    )
    _collect_cloud_scopes(SimpleNamespace(), state)
    assert state.cloud_scopes[0].name == "cloud:nebius"
    assert state.cloud_scopes[0].status.value == "partial"
    assert state.cloud_scopes[0].item_count == 2


@pytest.mark.parametrize("kubectl_available", [False, True])
def test_kubernetes_coverage_preserves_rest_inventory_and_scope(kubectl_available):
    from types import SimpleNamespace

    from agent_bom.cli.agents.scan_pipeline.report import _collect_cloud_scopes
    from agent_bom.cloud.nebius import discover
    from agent_bom.models import Agent, AgentType

    rest_agent = Agent(name="fixture-model", agent_type=AgentType.CUSTOM, config_path="nebius://fixture/model", source="nebius-ai-studio")
    with (
        patch("agent_bom.cloud.nebius.shutil.which", return_value="/fixture/kubectl" if kubectl_available else None),
        patch("agent_bom.cloud.nebius._discover_ai_studio", return_value=([rest_agent], [])),
        patch("agent_bom.cloud.nebius._discover_gpu_instances", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_container_services", return_value=([], [])),
        patch(
            "agent_bom.cloud.nebius._kubectl_get_all_pods", return_value=SimpleNamespace(returncode=0, stdout='{"items": []}')
        ) as kubectl,
    ):
        agents, warnings = discover(api_key="fixture-key", project_id="fixture-project")
    assert agents == [rest_agent]
    assert kubectl.call_count == (1 if kubectl_available else 0)  # both Kubernetes passes share one read
    if kubectl_available:
        assert warnings == []
    else:
        assert len(warnings) == 2
        assert any("GPU pod" in warning for warning in warnings)
        assert any("InfiniBand" in warning for warning in warnings)
        assert all("not tested" in warning for warning in warnings)
    state = SimpleNamespace(
        ctx=SimpleNamespace(
            cloud_provider_successes=[{"provider": "nebius", "item_count": len(agents)}],
            cloud_provider_warnings=[{"provider": "nebius", "warning": warning} for warning in warnings],
            cloud_provider_failures=[],
        )
    )
    _collect_cloud_scopes(SimpleNamespace(), state)
    assert state.cloud_scopes[0].status.value == ("complete" if kubectl_available else "partial")
    assert state.cloud_scopes[0].item_count == 1


@pytest.mark.parametrize("status,category", [(403, "denied"), (429, "throttled"), (503, "unavailable")])
@pytest.mark.parametrize("resource", ["models", "instances", "containers"])
def test_discovery_retains_completed_pages_when_next_request_fails(resource, status, category):
    import httpx

    from agent_bom.cloud.nebius import _discover_ai_studio, _discover_container_services

    collectors = {"models": _discover_ai_studio, "instances": _discover_gpu_instances, "containers": _discover_container_services}
    item = {"id": "kept", "name": "kept", "resources": {"gpus": 1}}
    failure = httpx.Response(status, request=httpx.Request("GET", "https://example.invalid/private-scope"), text="private-provider-body")
    with patch(
        "agent_bom.http_client.sync_request_with_retry",
        side_effect=[_response({resource: [item], "nextPageToken": "private-cursor"}), failure],
    ) as request:
        agents, warnings = collectors[resource]("fixture-key", "fixture-project")
    assert len(agents) == 1
    assert "kept" in agents[0].name
    assert request.call_count == 2
    assert len(warnings) == 1
    scope = "ai-studio" if resource == "models" else resource
    assert f"nebius:{scope}:{category}:" in warnings[0]
    assert "Assessment incomplete" in warnings[0]
    assert "private-" not in warnings[0]


@pytest.mark.parametrize("payload", [[], {"instances": "bad"}, {"instances": [], "nextPageToken": "private-cursor"}])
def test_discovery_retains_completed_pages_when_pagination_is_invalid(payload):
    with patch(
        "agent_bom.http_client.sync_request_with_retry",
        side_effect=[
            _response({"instances": [{"id": "kept", "resources": {"gpus": 1}}], "nextPageToken": "private-cursor"}),
            _response(payload),
        ],
    ) as request:
        agents, warnings = _discover_gpu_instances("fixture-key", "fixture-project")
    assert len(agents) == 1
    assert request.call_count == 2
    assert len(warnings) == 1
    assert "nebius:instances:unavailable:" in warnings[0]
    assert "private-cursor" not in warnings[0]


def test_partial_discovery_still_stops_at_page_limit():
    pages = [_response({"instances": [{"id": str(i), "resources": {"gpus": 1}}], "nextPageToken": str(i + 1)}) for i in range(50)]
    with patch("agent_bom.http_client.sync_request_with_retry", side_effect=pages) as request:
        agents, warnings = _discover_gpu_instances("fixture-key", "fixture-project")
    assert len(agents) == 50
    assert request.call_count == 50
    assert len(warnings) == 1
    assert "nebius:instances:unavailable:" in warnings[0]


def test_retry_exhaustion_retains_completed_inventory():
    with patch(
        "agent_bom.http_client.sync_request_with_retry",
        side_effect=[_response({"instances": [{"id": "kept", "resources": {"gpus": 1}}], "nextPageToken": "next"}), None],
    ):
        agents, warnings = _discover_gpu_instances("fixture-key", "fixture-project")
    assert len(agents) == 1
    assert len(warnings) == 1
    assert "nebius:instances:unavailable:" in warnings[0]
