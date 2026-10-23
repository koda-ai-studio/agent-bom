"""Bounded cloud capability probes distinguish credentials from usable access."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.cloud.capability_probe import (
    CapabilityProbeError,
    classify_probe_failure,
    probe_read_capability,
)


class _AwsSession:
    def __init__(self, client: object) -> None:
        self._client = client

    def client(self, service: str) -> object:
        assert service == "bedrock-agent"
        return self._client


def test_aws_probe_verifies_bedrock_read_capability() -> None:
    calls: list[dict[str, int]] = []
    client = SimpleNamespace(list_agents=lambda **kwargs: calls.append(kwargs) or {"agentSummaries": []})

    result = probe_read_capability("aws", _AwsSession(client), regions=["us-east-1"], auth_params={})

    assert result.capabilities == ("bedrock:list-agents",)
    assert calls == [{"maxResults": 1}]


def test_gcp_probe_verifies_vertex_read_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[dict[str, object], float]] = []

    class _EndpointClient:
        def __init__(self, *, credentials: object) -> None:
            assert credentials is credential

        def list_endpoints(self, *, request: dict[str, object], timeout: float):
            calls.append((request, timeout))
            return iter(())

    credential = object()
    fake_module = SimpleNamespace(EndpointServiceClient=_EndpointClient)
    monkeypatch.setattr("agent_bom.cloud.capability_probe._load_vertex_module", lambda: fake_module)

    result = probe_read_capability(
        "gcp",
        credential,
        regions=["us-central1"],
        auth_params={"project_id": "project-alpha"},
    )

    assert result.capabilities == ("vertex-ai:list-endpoints",)
    assert calls == [
        (
            {"parent": "projects/project-alpha/locations/us-central1", "page_size": 1},
            10.0,
        )
    ]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (type("NoCredentialsError", (Exception,), {})("secret.invalid"), "invalid_credentials"),
        (type("AccessDeniedException", (Exception,), {})("arn:aws:iam::123:role/private"), "permission_denied"),
        (TimeoutError("https://private.provider.invalid"), "timeout"),
    ],
)
def test_probe_failure_classification_is_stable_and_secret_free(exc: Exception, expected: str) -> None:
    classified = classify_probe_failure(exc)

    assert classified == expected
    assert "private" not in classified
    assert "secret" not in classified


def test_gcp_probe_requires_non_secret_project_scope() -> None:
    with pytest.raises(CapabilityProbeError) as exc_info:
        probe_read_capability("gcp", object(), regions=["us-central1"], auth_params={})

    assert exc_info.value.code == "invalid_configuration"
    assert "project" not in str(exc_info.value).lower()


@pytest.mark.parametrize("denied", [False, True])
def test_azure_probe_requires_a_bounded_resource_read(monkeypatch: pytest.MonkeyPatch, denied: bool) -> None:
    calls: list[dict] = []
    closed: list[bool] = []
    credential = object()

    class ResourceClient:
        def __init__(self, supplied_credential, subscription_id):
            assert supplied_credential is credential
            assert subscription_id == "test-subscription"
            self.resource_groups = self

        def __enter__(self):
            return self

        def __exit__(self, *_):
            closed.append(True)

        def list(self, **kwargs):
            calls.append(kwargs)
            if denied:
                raise type("HttpResponseError", (Exception,), {"status_code": 403})("private-provider-message")
            yield {"name": "first"}
            pytest.fail("readiness probe must not enumerate a second item")

    monkeypatch.setattr(
        "agent_bom.cloud.capability_probe._load_azure_resource_module",
        lambda: SimpleNamespace(ResourceManagementClient=ResourceClient),
    )
    if denied:
        with pytest.raises(CapabilityProbeError) as caught:
            probe_read_capability("azure", credential, regions=[], auth_params={"subscription_id": "test-subscription"})
        assert caught.value.code == "permission_denied"
        assert "private-provider-message" not in str(caught.value)
    else:
        result = probe_read_capability("azure", credential, regions=[], auth_params={"subscription_id": "test-subscription"})
        assert result.capabilities == ("azure-resource-groups:list",)
    assert calls == [{"top": 1, "connection_timeout": 10.0, "read_timeout": 10.0}]
    assert closed == [True]


def test_azure_token_alone_does_not_verify_inventory() -> None:
    # A valid management token without a subscription cannot prove read access.
    with pytest.raises(CapabilityProbeError) as caught:
        probe_read_capability("azure", SimpleNamespace(get_token=lambda *_: object()), regions=[], auth_params={})
    assert caught.value.code == "invalid_configuration"


def test_azure_probe_loader_resolves_the_pinned_resource_client() -> None:
    pytest.importorskip("azure.mgmt.resource.resources")
    from agent_bom.cloud.capability_probe import _load_azure_resource_module

    assert callable(_load_azure_resource_module().ResourceManagementClient)
