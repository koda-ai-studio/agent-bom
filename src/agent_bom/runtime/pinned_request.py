"""One outbound HTTP request under the delivery egress policy.

Preflight URL checks (scheme, private and metadata targets, with the operator
``AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS`` override), then a connection pinned to
the validated address with redirects and ambient proxies disabled.
"""

from __future__ import annotations

from agent_bom.core.settings import env_flag
from agent_bom.http_client import check_offline
from agent_bom.runtime import egress_transport
from agent_bom.security import SecurityError, sanitize_error, validate_url


def pinned_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    *,
    allow_private_networks: bool,
    require_operator_private_opt_in: bool = False,
) -> tuple[int | None, str, bool | None]:
    """Return ``(http_status, error, retryable)``; refused destinations are not retryable."""
    operator_private = env_flag("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS")
    allow_private = (
        (allow_private_networks and operator_private) if require_operator_private_opt_in else (allow_private_networks or operator_private)
    )
    try:
        validate_url(url, allowed_schemes=("https", "http") if allow_private else ("https",), allow_private=allow_private)
    except SecurityError as exc:
        return None, f"url rejected by outbound policy: {sanitize_error(exc)}", False
    try:
        check_offline()
        with egress_transport.build_pinned_sync_client(timeout=timeout, allow_private_networks=allow_private) as client:
            resp = client.request(method, url, content=body, headers=headers)
        return resp.status_code, "", None
    except egress_transport.UnsafeDestinationError:
        return None, "destination rejected at connect time by outbound policy", False
    except Exception as exc:  # noqa: BLE001 — any transport error becomes a retryable failure
        return None, sanitize_error(exc), None
