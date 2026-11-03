"""Names (never values) of credentials embedded in an MCP server launch config.

Each predicate mirrors :func:`agent_bom.security.sanitize_command_args` and
:func:`agent_bom.security.sanitize_url`: anything those redact on output is
counted here by a stable label, so inventory, blast radius and credential
exposure see the credential while the secret itself stays unread.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from agent_bom.domain.mcp_auth_headers import auth_header_names
from agent_bom.security import SENSITIVE_PATTERNS, _looks_sensitive_value

_SENSITIVE_NAME_RE = re.compile("|".join(f"(?:{pattern})" for pattern in SENSITIVE_PATTERNS))


def _sensitive_name(name: str) -> bool:
    return _SENSITIVE_NAME_RE.search(name.lower()) is not None


def url_credential_names(value: object) -> list[str]:
    """Labels for credentials carried in a URL's userinfo password or query."""
    if not isinstance(value, str) or "://" not in value:
        return []
    try:
        parsed = urlsplit(value)
    except ValueError:
        return []
    if not parsed.scheme or not parsed.netloc:
        return []
    scheme = parsed.scheme.lower()
    names: list[str] = []
    if "@" in parsed.netloc and ":" in parsed.netloc.rsplit("@", 1)[0]:
        names.append(f"{scheme}-url-password")
    names.extend(f"{scheme}-url-param:{key}" for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if _sensitive_name(key))
    return names


def _assignment_names(arg: str, index: int) -> list[str] | None:
    """Names for a ``key=value`` argument, or ``None`` when no branch applies."""
    key, _sep, raw_value = arg.partition("=")
    if _sensitive_name(key):
        return url_credential_names(arg) if "://" in key else [key]
    if "://" in raw_value:
        return url_credential_names(raw_value)
    if _looks_sensitive_value(raw_value):
        return [key or f"arg[{index}]"]
    return None


def command_arg_credential_names(args: Iterable[Any]) -> list[str]:
    """Labels for every argument ``sanitize_command_args`` would redact."""
    names: list[str] = []
    pending_flag: str | None = None
    for index, raw_arg in enumerate(args):
        arg = str(raw_arg)
        if pending_flag is not None:
            names.append(pending_flag)
            pending_flag = None
            continue
        if "=" in arg:
            found = _assignment_names(arg, index)
            if found is not None:
                names.extend(found)
                continue
        if "://" in arg:
            names.extend(url_credential_names(arg))
            continue
        if _looks_sensitive_value(arg):
            names.append(f"arg[{index}]")
            continue
        if arg.startswith("-") and _sensitive_name(arg):
            pending_flag = arg
    return names


def embedded_credential_names(args: Iterable[Any], url: object, header_names: object) -> list[str]:
    """Deduplicated credential labels from args, the server URL and auth headers."""
    headers = header_names if isinstance(header_names, list) else []
    labels = [
        *command_arg_credential_names(args),
        *url_credential_names(url),
        *(f"header:{name}" for name in auth_header_names(headers)),
    ]
    return list(dict.fromkeys(labels))
