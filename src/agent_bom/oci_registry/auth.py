"""Registry credentials and the distribution token flow — read-only.

Credentials are looked up only after a registry answers ``401``: explicit
arguments, then ``AGENT_BOM_REGISTRY_USER``/``AGENT_BOM_REGISTRY_PASS``, then
``~/.docker/config.json`` (``auths`` entries, ``credHelpers`` and
``credsStore`` via ``docker-credential-<helper> get``). Nothing is ever written
back, and credential values never reach logs or reports — only their source.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from agent_bom.image_evidence.model import as_dict
from agent_bom.oci_registry.reference import ImageReference

_CHALLENGE_PARAM_RE = re.compile(r'([A-Za-z_]+)\s*=\s*"([^"]*)"')
_HELPER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HELPER_TIMEOUT_SECONDS = 15
_MAX_CONFIG_BYTES = 1024 * 1024
_IDENTITY_TOKEN_USER = "<token>"


class RegistryAuthError(Exception):
    """The registry's auth challenge could not be satisfied."""


@dataclass(frozen=True)
class RegistryCredential:
    """Credential material plus where it came from (the only part ever reported)."""

    source: str
    username: str | None = None
    password: str | None = None
    identity_token: str | None = None

    @property
    def has_basic(self) -> bool:
        return bool(self.username and self.password)


ANONYMOUS = RegistryCredential(source="anonymous")


@dataclass(frozen=True)
class Challenge:
    scheme: str
    params: dict[str, str]


def parse_challenge(header: str | None) -> Challenge | None:
    """Parse a ``WWW-Authenticate`` header (``Bearer realm=..,service=..`` or ``Basic``)."""
    if not header:
        return None
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() not in {"bearer", "basic"}:
        return None
    return Challenge(scheme=scheme.lower(), params={k.lower(): v for k, v in _CHALLENGE_PARAM_RE.findall(rest)})


def docker_config_path() -> Path:
    base = os.environ.get("DOCKER_CONFIG")
    return (Path(base) if base else Path.home() / ".docker") / "config.json"


def _load_docker_config() -> dict:
    path = docker_config_path()
    try:
        if not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _from_auth_entry(entry: object) -> RegistryCredential | None:
    if not isinstance(entry, dict):
        return None
    token = entry.get("identitytoken")
    if isinstance(token, str) and token:
        return RegistryCredential(source="docker-config", identity_token=token)
    user, password = entry.get("username"), entry.get("password")
    if isinstance(user, str) and isinstance(password, str) and user and password:
        return RegistryCredential(source="docker-config", username=user, password=password)
    encoded = entry.get("auth")
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    user, sep, password = decoded.partition(":")
    return RegistryCredential(source="docker-config", username=user, password=password) if sep and user and password else None


def _run_credential_helper(helper: str, server: str) -> RegistryCredential | None:
    if not _HELPER_NAME_RE.match(helper):
        return None
    binary = shutil.which(f"docker-credential-{helper}")
    if binary is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed helper binary, server URL on stdin
            [binary, "get"],
            input=server,
            capture_output=True,
            text=True,
            timeout=_HELPER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        return None
    user, secret = payload.get("Username"), payload.get("Secret")
    if not isinstance(secret, str) or not secret:
        return None
    source = f"credential-helper:{helper}"
    if user == _IDENTITY_TOKEN_USER:
        return RegistryCredential(source=source, identity_token=secret)
    return RegistryCredential(source=source, username=str(user or ""), password=secret)


def _from_docker_config(ref: ImageReference) -> RegistryCredential | None:
    config = _load_docker_config()
    keys = ref.credential_keys()
    helpers = as_dict(config.get("credHelpers"))
    for key in keys:
        helper = helpers.get(key) or helpers.get(urlparse(key).netloc or key)
        if isinstance(helper, str):
            credential = _run_credential_helper(helper, key)
            if credential is not None:
                return credential
    auths = as_dict(config.get("auths"))
    for key in keys:
        credential = _from_auth_entry(auths.get(key))
        if credential is not None:
            return credential
    store = config.get("credsStore")
    if isinstance(store, str) and store:
        for key in keys:
            credential = _run_credential_helper(store, key)
            if credential is not None:
                return credential
    return None


def resolve_credential(ref: ImageReference, username: str | None = None, password: str | None = None) -> RegistryCredential:
    """Return the first credential that applies to ``ref`` (anonymous when none does)."""
    if username and password:
        return RegistryCredential(source="explicit", username=username, password=password)
    env_user, env_pass = os.environ.get("AGENT_BOM_REGISTRY_USER"), os.environ.get("AGENT_BOM_REGISTRY_PASS")
    if env_user and env_pass:
        return RegistryCredential(source="environment", username=env_user, password=env_pass)
    return _from_docker_config(ref) or ANONYMOUS


def validate_realm(realm: str, ref: ImageReference) -> str:
    """Accept a token realm only over HTTPS, and never on a link-local or private address."""
    parsed = urlparse(realm)
    host = (parsed.hostname or "").lower()
    if not host:
        raise RegistryAuthError("Registry token realm has no host")
    if ref.allows_plain_http and host in {"localhost", "127.0.0.1", "::1"}:
        return realm
    if parsed.scheme != "https":
        raise RegistryAuthError("Registry token realm must use HTTPS")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return realm
    if address.is_private or address.is_link_local or address.is_loopback or address.is_reserved or address.is_multicast:
        raise RegistryAuthError("Registry token realm points at a non-public address")
    return realm


def basic_header(credential: RegistryCredential) -> str | None:
    if not credential.has_basic:
        return None
    raw = f"{credential.username}:{credential.password}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")
