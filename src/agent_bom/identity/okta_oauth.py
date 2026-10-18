"""Private-key JWT authentication with ephemeral DPoP binding for Okta reads.

Only the two discovery scopes are requested. Tokens and DPoP private keys stay
in memory. Authentication fails closed; there is no client-secret fallback.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import time
import uuid
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_bom.core.settings import env_str
from agent_bom.identity.okta_http import org_origin, read_json

SCOPES = ("okta.apps.read", "okta.apiTokens.read")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class OktaOAuth:
    def __init__(self, org: str, client_id: str, private_key: bytes, key_id: str):
        self.origin = org_origin(org)
        self.client_id = client_id
        self.key_id = key_id
        signing_key = serialization.load_pem_private_key(private_key, password=None)
        if not isinstance(signing_key, rsa.RSAPrivateKey) or signing_key.key_size < 2048:
            raise ValueError("Okta signing requires an RSA private key of at least 2048 bits")
        self._signing_key = signing_key
        self._proof_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self._proof_key.public_key().public_numbers()
        self._jwk = {
            "kty": "RSA",
            **{k: _b64(v.to_bytes((v.bit_length() + 7) // 8, "big")) for k, v in (("e", numbers.e), ("n", numbers.n))},
        }
        self._access = ""
        self._expires = 0.0

    def _proof(self, method: str, url: str, nonce: str | None = None, access: str | None = None) -> str:
        target = urlsplit(url)
        claims: dict[str, Any] = {
            "htm": method,
            "htu": urlunsplit((target.scheme, target.netloc, target.path, "", "")),
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
        }
        if nonce:
            claims["nonce"] = nonce
        if access:
            claims["ath"] = _b64(hashlib.sha256(access.encode()).digest())
        return jwt.encode(claims, self._proof_key, algorithm="RS256", headers={"typ": "dpop+jwt", "jwk": self._jwk})

    def _authenticate(self, client: Any) -> None:
        url = self.origin + "/oauth2/v1/token"
        nonce = None
        for _ in range(2):
            now = int(time.time())
            assertion = jwt.encode(
                {"iss": self.client_id, "sub": self.client_id, "aud": url, "iat": now, "exp": now + 120, "jti": str(uuid.uuid4())},
                self._signing_key,
                algorithm="RS256",
                headers={"kid": self.key_id},
            )
            with client.stream(
                "POST",
                url,
                follow_redirects=False,
                headers={"DPoP": self._proof("POST", url, nonce)},
                data={
                    "grant_type": "client_credentials",
                    "scope": " ".join(SCOPES),
                    "client_id": self.client_id,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                },
            ) as response:
                payload = read_json(response)
                if not isinstance(payload, dict):
                    raise ValueError("Invalid Okta token response")
                challenge = response.headers.get("dpop-nonce")
                if response.status_code == 400 and payload.get("error") == "use_dpop_nonce" and challenge:
                    nonce = challenge
                    continue
                if response.status_code != 200:
                    raise ValueError("Okta OAuth authentication failed")
            access, lifetime = payload.get("access_token"), payload.get("expires_in")
            if (
                payload.get("token_type", "").lower() != "dpop"
                or not isinstance(payload.get("scope"), str)
                or set(payload["scope"].split()) != set(SCOPES)
                or not isinstance(access, str)
                or not access
                or not isinstance(lifetime, int)
                or isinstance(lifetime, bool)
                or lifetime <= 0
            ):
                raise ValueError("Unexpected Okta token contract")
            self._access = access
            self._expires = time.monotonic() + lifetime - min(30, lifetime / 2)
            return
        raise ValueError("Okta DPoP nonce exchange did not complete")

    def headers(self, client: Any, method: str, url: str) -> dict[str, str]:
        target = urlsplit(url)
        if target.scheme + "://" + target.netloc != self.origin or target.username or target.password or target.fragment:
            raise ValueError("Okta authentication destination mismatch")
        if not self._access or time.monotonic() >= self._expires:
            self._authenticate(client)
        return {"Authorization": "DPoP " + self._access, "DPoP": self._proof(method, url, access=self._access)}


def from_environment(org: str) -> OktaOAuth:
    """Load an owner-only local signing key; never accept a key value in env."""
    client_id = env_str("AGENT_BOM_OKTA_CLIENT_ID", "")
    key_id = env_str("AGENT_BOM_OKTA_KEY_ID", "")
    key_path = env_str("AGENT_BOM_OKTA_PRIVATE_KEY_FILE", "")
    if not client_id or not key_id or not key_path:
        raise ValueError("Okta OAuth requires client ID, key ID and private-key file")
    descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.getuid() or metadata.st_size > 16384:
            raise ValueError("Okta private-key file must be an owner-only regular file")
        key = stream.read(16385)
        if len(key) > 16384:
            raise ValueError("Okta private-key file exceeds bound")
    return OktaOAuth(org, client_id, key, key_id)
