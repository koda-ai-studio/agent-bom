"""A clustered API on a non-loopback listener refuses to start without attestation, so rendering refuses first."""

from __future__ import annotations

import pytest

from tests._helm_render import find, objects, render, requires_helm

pytestmark = requires_helm

_NO_ATTESTATION = {"api": {"listenerAttestation": {"fromSecret": False}}}
_TRUSTED_PROXY_ENV = [
    {"name": "AGENT_BOM_TRUST_PROXY_AUTH", "value": "1"},
    {"name": "AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "valueFrom": {"secretKeyRef": {"name": "proxy", "key": "secret"}}},
    {"name": "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER", "value": "edge"},
]
_MTLS_ENV = [
    {"name": "AGENT_BOM_TLS_CERT_FILE", "value": "/tls/tls.crt"},
    {"name": "AGENT_BOM_TLS_KEY_FILE", "value": "/tls/tls.key"},
    {"name": "AGENT_BOM_TLS_CLIENT_CA_FILE", "value": "/tls/ca.crt"},
    {"name": "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT", "value": "1"},
]


def _with(api: dict) -> dict:
    return {"api": {"listenerAttestation": {"fromSecret": False}, **api}}


@pytest.mark.parametrize(
    "control_plane",
    [
        _NO_ATTESTATION,
        _with({"replicas": 1, "autoscaling": {"enabled": True, "maxReplicas": 4}}),
        _with({"replicas": 1, "env": [{"name": "AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "value": "1"}]}),
        _with({"replicas": 1, "env": [{"name": "AGENT_BOM_DEPLOYMENT_ENV", "value": "production"}]}),
        _with({"env": [{"name": "AGENT_BOM_TRUST_PROXY_AUTH", "value": "0"}]}),
        _with({"env": _TRUSTED_PROXY_ENV[:2]}),
        _with({"env": _MTLS_ENV[:3]}),
    ],
)
def test_clustered_api_without_attestation_fails_rendering(control_plane: dict) -> None:
    result = render(control_plane)
    assert result.returncode != 0
    assert "AGENT_BOM_TRUST_PROXY_AUTH" in result.stderr
    assert "controlPlane.api.listenerAttestation.fromSecret" in result.stderr


@pytest.mark.parametrize(
    "control_plane",
    [
        {},
        _with({"env": _TRUSTED_PROXY_ENV}),
        _with({"env": _MTLS_ENV}),
        _with({"replicas": 1}),
        _with({"args": ["api", "--host", "127.0.0.1", "--port", "8422"]}),
    ],
)
def test_attested_or_single_loopback_api_renders(control_plane: dict) -> None:
    find(objects(render(control_plane)), "Deployment", "agent-bom-api")


def test_from_secret_requires_an_env_from_secret() -> None:
    result = render({"api": {"listenerAttestation": {"fromSecret": True}, "envFrom": []}})
    assert result.returncode != 0
    assert "controlPlane.api.envFrom" in result.stderr
    with_secret = {"api": {"listenerAttestation": {"fromSecret": True}, "envFrom": [{"secretRef": {"name": "auth"}}]}}
    find(objects(render(with_secret)), "Deployment", "agent-bom-api")


def test_disabled_api_is_not_checked() -> None:
    result = render({"api": {"enabled": False, "listenerAttestation": {"fromSecret": False}}})
    assert result.returncode == 0, result.stderr
