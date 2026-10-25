"""Explicit-credential Databricks workspace connection boundary."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from agent_bom.cloud.base import CloudDiscoveryError


def sdk_value(value: Any) -> str:
    """Normalize SDK enum members without serializing their Python repr."""
    raw = getattr(value, "value", value)
    return raw.upper() if isinstance(raw, str) else ""


def resolved_workspace_host(client: Any, fallback: str = "") -> str:
    """Use the authenticated SDK workspace, including OAuth profile resolution.

    This is inventory attribution, not credential destination validation. Strip
    non-origin components before recording it; stored-token connections still
    use the stricter ``workspace_host`` boundary below.
    """
    configured = getattr(getattr(client, "config", None), "host", None)
    value = configured if isinstance(configured, str) and configured else fallback
    parsed = urlsplit(value)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        return ""
    port = parsed.port
    suffix = f":{port}" if port and port != (443 if parsed.scheme == "https" else 80) else ""
    return f"{parsed.scheme}://{parsed.hostname}{suffix}"


def workspace_host(value: str) -> str:
    """Accept hosted workspace origins only, before a stored token is decrypted."""
    parsed = urlsplit(value.strip())
    host = parsed.hostname or ""
    suffixes = (".cloud.databricks.com", ".azuredatabricks.net", ".gcp.databricks.com")
    if (
        parsed.scheme != "https"
        or not host.endswith(suffixes)
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Use an HTTPS Databricks workspace origin without credentials, path or query.")
    return f"https://{host}"


def workspace_client(host: str, token: str) -> Any:
    """Never fall back to the control-plane host's ambient SDK credentials."""
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.core import Config

    if not token.strip():
        raise CloudDiscoveryError("A stored Databricks workspace token is required.")
    return WorkspaceClient(
        config=Config(host=workspace_host(host), token=token, auth_type="pat", http_timeout_seconds=10, retry_timeout_seconds=10)
    )


def validate_scan_options(host: str, inventory_scope: str | None, scan_mode: str, regions: list[str]) -> str:
    """Reject unsupported fan-out and event modes instead of accepting inert settings."""
    if inventory_scope not in (None, "account") or scan_mode != "full" or regions:
        raise ValueError("Databricks supports one workspace, full scans and no region selector; continuous events are unavailable.")
    return workspace_host(host)
