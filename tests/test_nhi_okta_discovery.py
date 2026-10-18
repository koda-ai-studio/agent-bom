"""Okta non-human-identity (NHI) discovery + graph projection.

All tests inject a fake Okta client — no live calls are ever made.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.nhi_overlay import apply_nhi_overlay, apply_nhi_overlay_from_result
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.identity.okta_nhi import (
    NHIDiscoveryStatus,
    discover_okta_non_human_identities,
)


class _FakeOktaClient:
    """Stand-in exposing the same read-only surface as ``OktaClient``."""

    def __init__(self, apps=None, tokens=None, fail_apps=False, fail_tokens=False):
        self._apps = apps or []
        self._tokens = tokens or []
        self._fail_apps = fail_apps
        self._fail_tokens = fail_tokens

    def list_oauth2_service_apps(self):
        if self._fail_apps:
            raise RuntimeError("403 Forbidden")
        return self._apps

    def list_api_tokens(self):
        if self._fail_tokens:
            raise RuntimeError("403 Forbidden")
        return self._tokens


def _service_app(app_id, label):
    return {
        "id": app_id,
        "label": label,
        "name": "oidc_client",
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "created": "2026-01-01T00:00:00Z",
        "lastUpdated": "2026-06-01T00:00:00Z",
        "settings": {
            "oauthClient": {
                "client_id": f"0oa{app_id}",
                "application_type": "service",
                "grant_types": ["client_credentials", "read_file"],
            }
        },
    }


def _human_app(app_id, label):
    # SAML/SSO human app — must be filtered out of NHI discovery.
    return {
        "id": app_id,
        "label": label,
        "status": "ACTIVE",
        "signOnMode": "SAML_2_0",
        "settings": {},
    }


def _api_token(token_id, name, user_id="00uHUMAN"):
    return {
        "id": token_id,
        "name": name,
        "status": "ACTIVE",
        "userId": user_id,
        "created": "2026-02-01T00:00:00Z",
        "lastUpdated": "2026-06-10T00:00:00Z",
        "expiresAt": "2026-09-01T00:00:00Z",
    }


# ── Enumeration → records ────────────────────────────────────────────────────


def test_discovers_service_accounts_and_api_tokens_filters_human_apps():
    client = _FakeOktaClient(
        apps=[_service_app("APP1", "billing-svc"), _human_app("APP2", "okta-dashboard")],
        tokens=[_api_token("TOK1", "ci-token")],
    )
    result = discover_okta_non_human_identities(client=client)

    assert result.status is NHIDiscoveryStatus.OK
    assert result.ok is True
    by_type = {i.identity_type for i in result.identities}
    assert by_type == {"service_account", "api_token"}
    assert len(result.identities) == 2  # human SAML app filtered out

    svc = next(i for i in result.identities if i.identity_type == "service_account")
    assert svc.identity_id == "APP1"
    assert svc.name == "billing-svc"
    assert svc.created_at == "2026-01-01T00:00:00Z"
    assert svc.scopes == ()
    assert svc.last_used_at is None
    assert svc.raw_identity["grant_types"] == ["client_credentials", "read_file"]

    tok = next(i for i in result.identities if i.identity_type == "api_token")
    assert tok.identity_id == "TOK1"
    assert tok.owner == "00uHUMAN"
    assert tok.last_used_at is None
    assert tok.credential_expires_at == "2026-09-01T00:00:00Z"


def test_empty_org_is_ok_with_no_identities():
    result = discover_okta_non_human_identities(client=_FakeOktaClient())
    assert result.status is NHIDiscoveryStatus.OK
    assert result.identities == ()


def test_partial_api_failure_still_returns_other_identities():
    client = _FakeOktaClient(apps=[_service_app("APP1", "svc")], fail_tokens=True)
    result = discover_okta_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.PARTIAL
    assert not result.ok
    assert [i.identity_type for i in result.identities] == ["service_account"]
    assert any("API-token listing failed" in w for w in result.warnings)


def test_total_api_failure_is_error_status_not_raise():
    client = _FakeOktaClient(fail_apps=True, fail_tokens=True)
    result = discover_okta_non_human_identities(client=client)
    assert result.status is NHIDiscoveryStatus.ERROR
    assert result.identities == ()
    assert len(result.warnings) == 2


# ── Flag gating ──────────────────────────────────────────────────────────────


def test_flag_off_returns_disabled_without_network(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_OKTA_DISCOVERY", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_ORG_URL", raising=False)
    result = discover_okta_non_human_identities()
    assert result.status is NHIDiscoveryStatus.DISABLED
    assert result.identities == ()
    assert any("disabled" in w.lower() for w in result.warnings)


def test_flag_on_but_missing_credentials(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "1")
    monkeypatch.delenv("AGENT_BOM_OKTA_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OKTA_ORG_URL", raising=False)
    result = discover_okta_non_human_identities()
    assert result.status is NHIDiscoveryStatus.MISSING_CREDENTIALS
    assert result.identities == ()
    warning = result.warnings[0]
    assert "AGENT_BOM_OKTA_TOKEN" in warning
    assert "AGENT_BOM_OKTA_ORG_URL" in warning


def test_flag_on_with_creds_uses_no_network_when_client_injected(monkeypatch):
    # Flag on + creds present, but an injected client means OktaClient (and thus
    # any HTTP) is never constructed.
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "true")
    monkeypatch.setenv("AGENT_BOM_OKTA_TOKEN", "ssws-xxx")
    monkeypatch.setenv("AGENT_BOM_OKTA_ORG_URL", "https://example.okta.com")
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("A", "svc")]))
    assert result.status is NHIDiscoveryStatus.OK
    assert len(result.identities) == 1


# ── Graph projection ─────────────────────────────────────────────────────────


def _graph_with_tool() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default")
    graph.add_node(UnifiedNode(id="tool:srv:read_file", entity_type=EntityType.TOOL, label="read_file"))
    return graph


def test_overlay_does_not_turn_oauth_grant_types_into_tool_permissions():
    client = _FakeOktaClient(
        apps=[_service_app("APP1", "billing-svc")],
        tokens=[_api_token("TOK1", "ci-token")],
    )
    result = discover_okta_non_human_identities(client=client)

    graph = _graph_with_tool()
    stats = apply_nhi_overlay(graph, result.identities)
    assert stats["nodes_added"] == 2

    mi_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    assert len(mi_nodes) == 2
    assert all(n.attributes["discovered"] is True for n in mi_nodes)
    assert all(n.attributes["provider"] == "okta" for n in mi_nodes)

    # Grant types are protocol flows, not permissions to similarly named tools.
    scoped = [(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.SCOPED_TO]
    assert scoped == []


def test_overlay_is_idempotent():
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]))
    graph = _graph_with_tool()
    first = apply_nhi_overlay(graph, result.identities)
    second = apply_nhi_overlay(graph, result.identities)
    assert first["nodes_added"] == 1
    assert second["nodes_added"] == 0


def test_overlay_from_result_noop_when_disabled():
    graph = _graph_with_tool()
    disabled = discover_okta_non_human_identities()  # flag off
    stats = apply_nhi_overlay_from_result(graph, disabled)
    assert stats == {"nodes_added": 0, "edges_added": 0}
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]


def test_managed_identity_nodes_are_consumable_by_effective_permissions():
    from agent_bom.graph.effective_permissions import _PRINCIPAL_TYPES

    # The discovered NHI uses MANAGED_IDENTITY, which the effective-permissions
    # engine already treats as a principal — so discovered identities feed it.
    assert EntityType.MANAGED_IDENTITY in _PRINCIPAL_TYPES

    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]))
    graph = _graph_with_tool()
    apply_nhi_overlay(graph, result.identities)
    principals = [n for n in graph.nodes.values() if n.entity_type in _PRINCIPAL_TYPES]
    assert len(principals) == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_provider_failure_does_not_echo_secret_exception():
    class Broken(_FakeOktaClient):
        def list_api_tokens(self):
            raise RuntimeError("secret-token-value https://internal.example/private")

    result = discover_okta_non_human_identities(client=Broken())
    assert result.status is NHIDiscoveryStatus.PARTIAL
    assert "secret-token-value" not in str(result)
    assert "internal.example" not in str(result)


def test_malformed_listing_is_not_successfully_empty():
    class Broken(_FakeOktaClient):
        def list_api_tokens(self):
            return {"error": "provider unavailable"}

    result = discover_okta_non_human_identities(client=Broken())
    assert result.status is NHIDiscoveryStatus.PARTIAL


def test_result_limit_is_reported_as_partial(monkeypatch):
    monkeypatch.setattr("agent_bom.identity.okta_nhi._MAX_RESULTS", 1)
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("A", "a"), _service_app("B", "b")]))
    assert result.status is NHIDiscoveryStatus.PARTIAL
    assert len(result.identities) == 1
    assert any("limit" in w for w in result.warnings)


def test_okta_identity_ids_are_scoped_to_org():
    graph = _graph_with_tool()
    for org in ("https://first.okta.com", "https://second.okta.com"):
        result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]), org_url=org)
        apply_nhi_overlay_from_result(graph, result)
    assert len([n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]) == 2


def test_oauth_configuration_constructs_client_without_ssws(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OKTA_DISCOVERY", "true")
    monkeypatch.setenv("AGENT_BOM_OKTA_ORG_URL", "https://example.okta.com")
    monkeypatch.setenv("AGENT_BOM_OKTA_CLIENT_ID", "fixture")
    monkeypatch.delenv("AGENT_BOM_OKTA_TOKEN", raising=False)
    monkeypatch.setattr("agent_bom.identity.okta_oauth.from_environment", lambda org: object())
    monkeypatch.setattr("agent_bom.identity.okta_nhi.OktaClient", lambda *a, **kw: _FakeOktaClient())
    assert discover_okta_non_human_identities().ok


def test_scoped_okta_graph_contains_observed_org_membership():
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.nhi_overlay import serialize_discovery_result

    result = discover_okta_non_human_identities(
        client=_FakeOktaClient(apps=[_service_app("APP1", "svc")]), org_url="https://example.okta.com"
    )
    graph = build_unified_graph_from_report(
        {"scan_id": "fixture", "tenant_id": "fixture", "identity_discovery": serialize_discovery_result(result)}
    )
    assert len([n for n in graph.nodes.values() if n.entity_type == EntityType.ACCOUNT]) == 1
    assert any(e.relationship == RelationshipType.MEMBER_OF for e in graph.edges)
    assert graph.contract_rejections.total == 0


@pytest.mark.parametrize("oauth", [None, [], {"grant_types": [{"client_secret": "never-export"}]}])
def test_malformed_nested_app_metadata_is_partial_without_exception(oauth):
    app = _service_app("APP1", "svc")
    app["settings"]["oauthClient"] = oauth
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[app]))
    assert result.status is NHIDiscoveryStatus.PARTIAL
    assert "never-export" not in repr(result)


def test_authentication_configuration_is_metadata_only():
    app = _service_app("APP1", "svc")
    app["credentials"] = {
        "oauthClient": {"client_id": "client-1", "token_endpoint_auth_method": "private_key_jwt", "client_secret": "never-export"}
    }
    app["settings"]["oauthClient"]["dpop_bound_access_tokens"] = True
    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[app]))
    raw = result.identities[0].raw_identity
    assert raw["client_id"] == "client-1"
    assert raw["client_authentication"] == "private_key_jwt"
    assert raw["dpop_bound_access_tokens"] is True
    assert "never-export" not in repr(result)


def test_merged_discovery_keeps_partial_coverage_visible():
    from agent_bom.graph.nhi_overlay import merge_discovery_results

    result = discover_okta_non_human_identities(client=_FakeOktaClient(apps=[_service_app("APP1", "svc")], fail_tokens=True))
    merged = merge_discovery_results([result])
    assert merged["status"] == "partial"
    assert merged["providers"][0]["provider"] == "okta"
    assert merged["providers"][0]["coverage"][1]["state"] == "unknown"


def test_invalid_org_url_does_not_echo_embedded_credentials():
    result = discover_okta_non_human_identities(org_url="https://user:never-export@example.okta.com", token="fixture-token", force=True)
    assert not result.ok
    assert result.org_url is None
    assert "never-export" not in repr(result)
