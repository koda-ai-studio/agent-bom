"""Synthetic Keycloak realm for the identity lane.

Follows the setup in docs/MCP_OAUTH.md. All users, clients and secrets are
generated per run and exist only inside the run's disposable Keycloak.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

REALM = "agent-bom"
ISSUER_ORIGIN = "https://localhost:8443"
ISSUER = f"{ISSUER_ORIGIN}/realms/{REALM}"
MCP_AUDIENCE = "https://mcp.qualification.test/mcp"
API_AUDIENCE = "agent-bom-api"
SAML_SP_ENTITY = "https://agent-bom.qualification.test/saml/metadata"
SAML_URL_NAME = "agent-bom"
BROWSER_CLIENT = "agent-bom-ui"
USER_NAME = "qualification-user"
USER_TENANT = "tenant-a"
ROLE = "analyst"

MCP_PROBES = {
    "probe-tenant-a": "tenant-a",
    "probe-tenant-b": "tenant-b",
    "probe-unapproved": "tenant-a",
    "probe-expiring": "tenant-a",
    "probe-revoked": "tenant-a",
}
API_PROBES = {"api-tenant-a": "tenant-a", "api-tenant-b": "tenant-b"}


@dataclass
class RealmSecrets:
    user_password: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    browser_client: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    introspection_client: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    probes: dict[str, str] = field(default_factory=dict)

    def probe(self, name: str) -> str:
        return self.probes.setdefault(name, secrets.token_urlsafe(32))


def _claim_flags() -> dict[str, str]:
    return {"access.token.claim": "true", "id.token.claim": "true", "introspection.token.claim": "true"}


def _hardcoded(name: str, value: str) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": name, "claim.value": value, "jsonType.label": "String", **_claim_flags()},
    }


def _audience(name: str, audience: str) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.custom.audience": audience,
            "access.token.claim": "true",
            "id.token.claim": "true",
            "introspection.token.claim": "true",
        },
    }


def _service_client(
    client_id: str, secret: str, *, tenant: str, audience: str, scopes: list[str], lifespan: int | None = None
) -> dict[str, Any]:
    attributes = {"access.token.lifespan": str(lifespan)} if lifespan else {}
    return {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": secret,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "defaultClientScopes": ["basic", *scopes],
        "optionalClientScopes": [],
        "attributes": attributes,
        "protocolMappers": [_hardcoded("tenant_id", tenant), _hardcoded("agent_bom_role", ROLE), _audience("audience", audience)],
    }


def _client_scopes() -> list[dict[str, Any]]:
    scope_attributes = {"include.in.token.scope": "true", "display.on.consent.screen": "false"}
    return [
        {
            "name": "basic",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
            "protocolMappers": [
                {
                    "name": "sub",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true", "introspection.token.claim": "true"},
                }
            ],
        },
        {
            "name": "read",
            "protocol": "openid-connect",
            "attributes": scope_attributes,
            "protocolMappers": [_audience("mcp-audience", MCP_AUDIENCE)],
        },
    ]


def _saml_client(acs_url: str) -> dict[str, Any]:
    def attribute(name: str, value: str) -> dict[str, Any]:
        return {
            "name": name,
            "protocol": "saml",
            "protocolMapper": "saml-hardcode-attribute-mapper",
            "config": {"attribute.name": name, "attribute.value": value, "attribute.nameformat": "Basic"},
        }

    return {
        "clientId": SAML_SP_ENTITY,
        "enabled": True,
        "protocol": "saml",
        "redirectUris": [acs_url],
        "attributes": {
            "saml_assertion_consumer_url_post": acs_url,
            "saml_idp_initiated_sso_url_name": SAML_URL_NAME,
            "saml.assertion.signature": "true",
            "saml.server.signature": "true",
            "saml.client.signature": "false",
            "saml.force.post.binding": "true",
            "saml.signature.algorithm": "RSA_SHA256",
            "saml_name_id_format": "username",
        },
        "protocolMappers": [attribute("tenant_id", USER_TENANT), attribute("agent_bom_role", ROLE)],
    }


def build_realm(realm_secrets: RealmSecrets, *, redirect_uri: str, saml_acs_url: str) -> dict[str, Any]:
    clients = [
        {
            "clientId": BROWSER_CLIENT,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": realm_secrets.browser_client,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [redirect_uri],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "defaultClientScopes": ["basic"],
            "protocolMappers": [
                _hardcoded("tenant_id", USER_TENANT),
                _hardcoded("agent_bom_role", ROLE),
                {
                    "name": "username",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-property-mapper",
                    "config": {
                        "user.attribute": "username",
                        "claim.name": "preferred_username",
                        "jsonType.label": "String",
                        **_claim_flags(),
                    },
                },
            ],
        },
        {
            "clientId": MCP_AUDIENCE,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": realm_secrets.introspection_client,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
        },
        _saml_client(saml_acs_url),
    ]
    for name, tenant in MCP_PROBES.items():
        clients.append(
            _service_client(
                name,
                realm_secrets.probe(name),
                tenant=tenant,
                audience=MCP_AUDIENCE,
                scopes=["read"],
                lifespan=5 if name == "probe-expiring" else None,
            )
        )
    clients.append(
        _service_client(
            "probe-other-audience",
            realm_secrets.probe("probe-other-audience"),
            tenant="tenant-a",
            audience="https://other.qualification.test/mcp",
            scopes=[],
        )
    )
    for name, tenant in API_PROBES.items():
        clients.append(_service_client(name, realm_secrets.probe(name), tenant=tenant, audience=API_AUDIENCE, scopes=[]))
    service_clients = [*MCP_PROBES, "probe-other-audience", *API_PROBES]
    users: list[dict[str, Any]] = [
        {
            "username": USER_NAME,
            "enabled": True,
            "email": "qualification-user@example.invalid",
            "emailVerified": True,
            "firstName": "Qualification",
            "lastName": "User",
            "credentials": [{"type": "password", "value": realm_secrets.user_password, "temporary": False}],
        }
    ]
    users += [{"username": f"service-account-{name}", "enabled": True, "serviceAccountClientId": name} for name in service_clients]
    return {
        "realm": REALM,
        "enabled": True,
        "registrationAllowed": False,
        "sslRequired": "external",
        "accessTokenLifespan": 300,
        "clientScopes": _client_scopes(),
        "defaultDefaultClientScopes": ["basic"],
        "clients": clients,
        "users": users,
    }
