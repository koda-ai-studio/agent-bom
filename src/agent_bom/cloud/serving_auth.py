"""Bearer tokens for protected self-hosted serving endpoints.

An operator pairs one probed endpoint with one dedicated environment variable
(``AGENT_BOM_SERVING_TOKEN_<NAME>``, or ``<that>_FILE`` for a mounted secret,
which wins, as in :func:`agent_bom.api.secret_source.resolve_secret`). The
token is never accepted as a command-line value, in a URL, or from any other
variable, and it is sent only to the endpoint it is paired with. Only
``request_identity`` (``bearer`` or ``anonymous``) is recorded as evidence.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from agent_bom.core.settings import env_str

TOKEN_ENV_PREFIX = "AGENT_BOM_SERVING_TOKEN_"
_TOKEN_ENV_NAME = re.compile(r"^AGENT_BOM_SERVING_TOKEN_[A-Z0-9][A-Z0-9_]*$")
# RFC 6750 b64token characters; anything else could split or inject a header.
_BEARER_TOKEN = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")


class ServingAuthError(Exception):
    """A configured token cannot be used; the message never contains the value."""


def validate_token_env_name(name: str) -> str:
    """Return *name* if it is a dedicated serving-token variable, else raise ``ValueError``."""
    candidate = (name or "").strip()
    if not _TOKEN_ENV_NAME.match(candidate) or candidate.endswith("_FILE"):
        raise ValueError(f"token variable must be named {TOKEN_ENV_PREFIX}<NAME> (uppercase, without _FILE)")
    return candidate


def endpoint_key(url: str) -> str:
    """Comparable identity of an endpoint: scheme, lowercase host, effective port and path."""
    parts = urlsplit(str(url).strip())
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme.lower())
    except ValueError:
        port = None
    return f"{parts.scheme.lower()}://{host}:{port}{parts.path.rstrip('/')}"


def pair_token_envs(endpoints: Iterable[tuple[str, str]], token_envs: Iterable[tuple[str, str]]) -> list[tuple[str, str, str | None]]:
    """Attach each token variable to exactly the endpoint it names.

    Raises ``ValueError`` for a pairing whose endpoint is not probed or that is
    paired twice, so a token can never silently go unused or to another host.
    """
    by_key: dict[str, str] = {}
    for url, env_name in token_envs:
        key = endpoint_key(url)
        if key in by_key:
            raise ValueError(f"endpoint {url} is paired with more than one token variable")
        by_key[key] = validate_token_env_name(env_name)
    paired = [(runtime, url, by_key.get(endpoint_key(url))) for runtime, url in endpoints]
    probed = {endpoint_key(url) for _runtime, url in endpoints}
    unmatched = sorted(key for key in by_key if key not in probed)
    if unmatched:
        raise ValueError("token variable paired with an endpoint that is not probed: " + ", ".join(unmatched))
    return paired


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _resolve_token(name: str) -> str:
    """``{name}_FILE`` wins when set; errors name the variable, never the path or value."""
    file_path = env_str(f"{name}_FILE")
    if not file_path:
        return env_str(name)
    path = Path(file_path)
    try:
        value = path.read_text(encoding="utf-8").strip("\r\n") if path.is_file() else None
    except (OSError, UnicodeDecodeError):
        value = None
    if value is None:
        raise ServingAuthError(f"bearer token unavailable: the file named by {name}_FILE cannot be read")
    if not value:
        raise ServingAuthError(f"bearer token unavailable: the file named by {name}_FILE is empty")
    return value


def bearer_token(env_name: str, endpoint: str) -> str:
    """Resolve the token for *endpoint*; raise ``ServingAuthError`` when it must not be sent."""
    name = validate_token_env_name(env_name)
    parts = urlsplit(endpoint)
    if parts.scheme != "https" and not _is_loopback((parts.hostname or "").lower()):
        raise ServingAuthError("a bearer token is sent only over https or to a loopback address")
    token = _resolve_token(name)
    if not token:
        raise ServingAuthError(f"bearer token unavailable: {name} or {name}_FILE is not set")
    if not _BEARER_TOKEN.match(token):
        raise ServingAuthError(f"bearer token in {name} contains characters a bearer token cannot carry")
    return token
