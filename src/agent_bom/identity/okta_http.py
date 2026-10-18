"""Bounded Okta reads with credentials confined to one tenant and endpoint."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

MAX_PAGES = 20
MAX_RECORDS = 2000
MAX_BYTES = 2 * 1024 * 1024


def org_origin(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not any(host.endswith(suffix) for suffix in (".okta.com", ".oktapreview.com", ".okta-emea.com"))
    ):
        raise ValueError("An HTTPS Okta tenant origin is required")
    return f"https://{host}"


def read_json(response: Any) -> Any:
    data = bytearray()
    for chunk in response.iter_bytes():
        data.extend(chunk)
        if len(data) > MAX_BYTES:
            raise ValueError("Okta response exceeded collection bound")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise ValueError("Okta returned invalid JSON") from None


class MetadataReader:
    def __init__(self, org: str, token: str, *, auth: Any = None, transport: Any = None):
        self.origin = org_origin(org)
        self.token = token
        self.auth = auth
        self.transport = transport

    def collect(self, path: str) -> list[dict[str, Any]]:
        import httpx

        endpoint = urlsplit(path).path
        url = self.origin + path
        visited: set[str] = set()
        ids: set[str] = set()
        records: list[dict[str, Any]] = []
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=20, transport=self.transport) as client:
            for _ in range(MAX_PAGES):
                target = urlsplit(url)
                if (
                    target.scheme + "://" + target.netloc != self.origin
                    or target.path != endpoint
                    or target.username
                    or target.password
                    or target.fragment
                    or url in visited
                ):
                    raise ValueError("Invalid Okta pagination destination or repeated page")
                visited.add(url)
                headers = self.auth.headers(client, "GET", url) if self.auth else {"Authorization": f"SSWS {self.token}"}
                headers["Accept"] = "application/json"
                with client.stream("GET", url, headers=headers) as response:
                    if response.status_code != 200:
                        raise ValueError("Okta metadata request failed")
                    payload = read_json(response)
                    next_url = response.links.get("next", {}).get("url")
                if not isinstance(payload, list):
                    raise ValueError("Invalid Okta metadata page")
                for record in payload:
                    if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"] or record["id"] in ids:
                        raise ValueError("Invalid or duplicate Okta metadata record")
                    ids.add(record["id"])
                    records.append(record)
                if len(records) > MAX_RECORDS:
                    raise ValueError("Okta record collection bound reached")
                if not next_url:
                    return records
                url = next_url
        raise ValueError("Okta page collection bound reached")
