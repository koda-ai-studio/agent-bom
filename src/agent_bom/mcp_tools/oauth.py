"""Read-only MCP resource-server authentication with an operator-owned issuer.

The issuer owns login, consent and renewable credentials. This module never
registers clients or issues tokens. A signed tenant claim must match the explicit
deployment tenant. Live introspection checks revocation on every HTTP request.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import urlsplit

from agent_bom.api.secret_source import resolve_secret
from agent_bom.mcp_tenant import mcp_tenant_bound, resolve_mcp_tenant_id
from agent_bom.mcp_tools.oauth_http import issuer_json

_ENV_NAMES = {
    "ISSUER": "AGENT_BOM_MCP_OAUTH_ISSUER",
    "AUDIENCE": "AGENT_BOM_MCP_OAUTH_AUDIENCE",
    "JWKS_URI": "AGENT_BOM_MCP_OAUTH_JWKS_URI",
    "SUBJECTS": "AGENT_BOM_MCP_OAUTH_SUBJECTS",
    "INTROSPECTION_URL": "AGENT_BOM_MCP_OAUTH_INTROSPECTION_URL",
    "INTROSPECTION_CLIENT_ID": "AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_ID",
}
_SECRET_ENV = "AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_SECRET"


def oauth_configured() -> bool:
    return any(os.environ.get(name, "").strip() for name in (*_ENV_NAMES.values(), _SECRET_ENV, _SECRET_ENV + "_FILE"))


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP OAuth URLs must be absolute HTTPS URLs without credentials, queries or fragments")
    return value


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    audience: str
    jwks_uri: str
    subjects: frozenset[str]
    tenant_id: str
    introspection_url: str
    introspection_client_id: str
    introspection_client_secret: str = field(repr=False)

    @classmethod
    def from_env(cls) -> OAuthConfig:
        values = {key: os.environ.get(name, "").strip() for key, name in _ENV_NAMES.items()}
        if not all(values.values()):
            raise ValueError("MCP OAuth requires issuer, audience, JWKS, subjects and introspection settings")
        if not mcp_tenant_bound():
            raise ValueError("MCP OAuth requires an explicit deployment tenant")
        subjects = frozenset(s.strip() for s in values["SUBJECTS"].split(",") if s.strip())
        if not subjects or "*" in subjects:
            raise ValueError("MCP OAuth requires explicit approved subjects; wildcards are not supported")
        issuer, jwks = _https_url(values["ISSUER"]), _https_url(values["JWKS_URI"])
        if urlsplit(issuer).netloc != urlsplit(jwks).netloc:
            raise ValueError("MCP OAuth JWKS must use the configured issuer origin")
        introspection = _https_url(values["INTROSPECTION_URL"])
        if urlsplit(issuer).netloc != urlsplit(introspection).netloc:
            raise ValueError("MCP OAuth introspection must use the configured issuer origin")
        return cls(
            issuer,
            _https_url(values["AUDIENCE"]),
            jwks,
            subjects,
            resolve_mcp_tenant_id(),
            introspection,
            values["INTROSPECTION_CLIENT_ID"],
            resolve_secret(_SECRET_ENV, required=True),
        )


class OAuthTokenVerifier:
    """Verify signatures with cached, rotating public keys and bounded lifetimes."""

    def __init__(self, config: OAuthConfig):
        try:
            import jwt
        except ImportError as exc:
            raise ValueError("MCP OAuth requires agent-bom[oidc]") from exc
        self.config = config

        class TrustedKeys(jwt.PyJWKClient):
            _last_fetch = 0.0

            def fetch_data(self):
                import time

                # Unknown key IDs must not turn every rejected token into an
                # issuer request. A rotated key can be retried after this bound.
                now = time.monotonic()
                if now - self._last_fetch < 10:
                    raise ValueError("MCP OAuth key refresh is rate limited")
                self._last_fetch = now

                data = issuer_json(self.uri)
                if not isinstance(data.get("keys"), list):
                    raise ValueError("Invalid MCP OAuth JWKS")
                if self.jwk_set_cache is not None:
                    self.jwk_set_cache.put(cast(Any, data))
                return data

        self.keys = TrustedKeys(config.jwks_uri, cache_jwk_set=True, lifespan=300)
        # Serialize key refresh to keep one consistent cache across callers.
        self._lock = asyncio.Lock()

    def _verify(self, token: str):
        import time

        import jwt
        from mcp.server.auth.provider import AccessToken

        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={"require": ["iss", "aud", "sub", "iat", "exp", "tenant_id"]},
            )
            issued, expires = claims["iat"], claims["exp"]
            if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= 3600:
                return None
            if expires <= time.time() or issued > time.time():
                return None
            if claims["sub"] not in self.config.subjects:
                return None
            if not isinstance(claims["tenant_id"], str) or claims["tenant_id"] != self.config.tenant_id:
                return None
            scope = claims.get("scope")
            if not isinstance(scope, str):
                return None
            if not self._active(token, claims):
                return None
            # Identity and administrative claims cannot grant write authority.
            return AccessToken(
                token=token,
                client_id="oauth:" + self.config.tenant_id + ":" + claims["sub"],
                scopes=["read"] if "read" in scope.split() else [],
                expires_at=expires,
                resource=self.config.audience,
                subject=claims["sub"],
                claims={"iss": self.config.issuer, "tenant_id": self.config.tenant_id},
            )
        except Exception:  # noqa: BLE001 — auth failures fail closed; never log token or remote exception
            return None

    def _active(self, token: str, claims: dict[str, Any]) -> bool:
        result = issuer_json(
            self.config.introspection_url,
            data={"token": token, "token_type_hint": "access_token"},
            auth=(self.config.introspection_client_id, self.config.introspection_client_secret),
        )
        # Never cache a successful revocation decision. An issuer outage, missing
        # claims, or a disagreement with signed identity is a denial, not fallback.
        return result.get("active") is True and all(
            result.get(name) == claims[name] for name in ("iss", "sub", "aud", "exp", "tenant_id", "scope")
        )

    async def verify_token(self, token: str):
        if not token or len(token) > 16384:
            return None
        async with self._lock:
            return await asyncio.to_thread(self._verify, token)
