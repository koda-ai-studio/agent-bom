"""Bounded bearer-authenticated metadata reads for management collectors."""

from __future__ import annotations

import json
from typing import Any

import httpx


def read_json(client: httpx.Client, url: str, token: str, *, max_bytes: int, params: dict[str, Any] | None = None) -> tuple[Any, str]:
    """Never follow redirects or retain provider error bodies in collection receipts."""
    try:
        with client.stream(
            "GET", url, params=params, headers={"Authorization": "Bearer " + token}, follow_redirects=False, timeout=20
        ) as response:
            if response.status_code != 200:
                return None, {401: "unauthenticated", 403: "denied", 429: "rate_limited"}.get(response.status_code, "unavailable")
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=65536):
                if len(body) + len(chunk) > max_bytes:
                    return None, "response_limit"
                body.extend(chunk)
            return json.loads(body), "read"
    except (httpx.HTTPError, UnicodeError, ValueError):
        return None, "unavailable"
