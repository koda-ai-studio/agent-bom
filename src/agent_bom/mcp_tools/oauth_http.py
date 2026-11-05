"""Bounded, TLS-verified requests to the configured MCP authorization server."""

from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.parse import quote_plus

from agent_bom.core.settings import env_str


def issuer_json(url: str, *, data: dict[str, str] | None = None, auth: tuple[str, str] | None = None) -> dict[str, Any]:
    import httpx

    from agent_bom.security import validate_url

    validate_url(url)
    # RFC 6749 section 2.3.1 encodes each credential before HTTP Basic.
    if auth is not None:
        auth = (quote_plus(auth[0]), quote_plus(auth[1]))
    # Respect the operator's explicit CA bundle without inheriting HTTP proxies.
    tls = ssl.create_default_context(cafile=env_str("SSL_CERT_FILE") or None)
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False, verify=tls) as client:
        with client.stream("POST" if data is not None else "GET", url, data=data, auth=auth) as response:
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > 262144:
                    raise ValueError("MCP OAuth issuer response exceeds size limit")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ValueError("MCP OAuth issuer response must be an object")
    return result
