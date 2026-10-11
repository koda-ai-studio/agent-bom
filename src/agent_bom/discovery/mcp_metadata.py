"""Sanitized MCP connection evidence; configuration is not runtime enforcement."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_sensitive_payload, sanitize_text

_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def connection_metadata(config: dict, root: dict) -> dict[str, Any]:
    """Retain declarations, never header values or OAuth secrets."""
    result: dict[str, Any] = {}
    headers = config.get("headers", config.get("http_headers", {}))
    env_headers = config.get("env_http_headers", {})
    names = set(headers if isinstance(headers, dict) else ()) | set(env_headers if isinstance(env_headers, dict) else ())
    if config.get("bearer_token_env_var"):
        names.add("Authorization")
    if names:
        result["header_names"] = sorted(n for n in names if isinstance(n, str) and _HEADER.fullmatch(n))[:64]
    oauth = config.get("oauth")
    if isinstance(oauth, dict):
        result["oauth_configured"] = True
        result["oauth_enterprise_managed"] = oauth.get("enterpriseManaged") is True
    for key in ("sandboxEnabled", "enabled", "disabled"):
        if isinstance(config.get(key), bool):
            result[key] = config[key]
    sandbox = root.get("sandbox")
    if isinstance(sandbox, dict):
        result["sandbox"] = {}
        for section, keys in [("network", ("allowedDomains", "deniedDomains")), ("filesystem", ("allowWrite", "denyRead", "denyWrite"))]:
            values = sandbox.get(section)
            if isinstance(values, dict):
                result["sandbox"][section] = {
                    k: [sanitize_text(v[:2048]) for v in values[k][:64] if isinstance(v, str)]
                    for k in keys
                    if isinstance(values.get(k), list)
                }
        result["sandbox_evidence"] = "configured-not-verified"
    return result


def scan_auth_headers(server: Any) -> dict[str, str]:
    """Resolve only an operator-selected auth file, bound to exact server and URL.

    Discovered config cannot select this file or authorize credential use.
    Values are environment references; neither refs' values nor headers persist.
    """
    filename = env_raw("AGENT_BOM_MCP_SCAN_AUTH_FILE")
    if not filename:
        return {}
    path = Path(filename)
    if path.stat().st_size > 65536:
        raise ValueError("MCP scan auth file exceeds 64 KiB")
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("MCP scan auth file must be an object")
    entry = data.get(server.canonical_id)
    if entry is None:
        return {}
    if not isinstance(entry, dict) or entry.get("url") != server.url:
        raise ValueError("MCP scan auth endpoint binding mismatch")
    refs = entry.get("header_env", {})
    if not isinstance(refs, dict) or len(refs) > 32:
        raise ValueError("Invalid MCP scan auth header references")
    result = {}
    for name, env in refs.items():
        if (
            not isinstance(name, str)
            or not _HEADER.fullmatch(name)
            or name.lower().startswith("mcp-")
            or name.lower() in {"host", "content-length", "transfer-encoding", "connection", "content-type", "accept"}
        ):
            raise ValueError("Invalid MCP scan auth header name")
        if not isinstance(env, str) or not _ENV.fullmatch(env):
            raise ValueError("Invalid MCP scan auth environment reference")
        value = env_raw(env)
        if not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Missing or invalid MCP scan authentication value")
        result[name] = value
    return result


def ui_metadata(meta: object) -> dict:
    """Retain bounded Apps declarations as untrusted inventory evidence."""
    if not isinstance(meta, dict) or not isinstance(meta.get("ui"), dict):
        return {}
    ui = meta["ui"]
    selected = {key: ui[key] for key in ("resourceUri", "visibility", "csp", "permissions") if key in ui}
    encoded = json.dumps(selected)
    if len(encoded) > 32768:
        return {"evidence_status": "oversized-metadata"}
    sanitized = sanitize_sensitive_payload(selected, max_str_len=2048)
    assert isinstance(sanitized, dict)
    return sanitized


async def apps_resource_evidence(session: Any, uri: str) -> dict:
    """Read linked UI resources as inventory evidence without executing HTML."""
    try:
        resource = await session.read_resource(uri)
        evidence = []
        for item in getattr(resource, "contents", [])[:4]:
            html = getattr(item, "text", None)
            if not isinstance(html, str) or len(html) > 1024 * 1024:
                return {"resource_status": "unsupported-or-oversized"}
            evidence.append(
                {
                    "sha256": hashlib.sha256(html.encode()).hexdigest(),
                    "mime_type": getattr(item, "mime_type", None),
                    "ui": ui_metadata(getattr(item, "meta", None)),
                }
            )
        return {"resources": evidence}
    except Exception:
        return {"resource_status": "unavailable"}


async def capability_items(session: Any, method: str, field: str) -> list[Any]:
    """Read a bounded complete catalog; a repeated cursor is incomplete evidence."""
    cursor = None
    seen = set()
    items = []
    for _ in range(20):
        listing = await getattr(session, method)(**({"cursor": cursor} if cursor else {}))
        items.extend(getattr(listing, field))
        if len(items) > 5000:
            raise ValueError("MCP capability catalog exceeds limit")
        cursor = getattr(listing, "next_cursor", None)
        if cursor is None:
            return items
        if not isinstance(cursor, str) or not cursor or cursor in seen:
            raise ValueError("Invalid MCP capability pagination")
        seen.add(cursor)
    raise ValueError("MCP capability pagination exceeds limit")
