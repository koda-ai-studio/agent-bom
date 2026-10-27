"""Operator-owned upstream limits, validated before gateway startup I/O."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

import click

from agent_bom.security import sanitize_error

_OPTIONS: tuple[tuple[str, type[int] | type[float], int | float, str, str], ...] = (
    ("upstream_http_max_connections", int, 100, "AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_CONNECTIONS", "Maximum upstream HTTP connections."),
    (
        "upstream_http_max_keepalive_connections",
        int,
        20,
        "AGENT_BOM_GATEWAY_UPSTREAM_HTTP_MAX_KEEPALIVE_CONNECTIONS",
        "Maximum idle upstream connections; cannot exceed the total pool.",
    ),
    ("upstream_http_timeout_seconds", float, 30.0, "AGENT_BOM_GATEWAY_UPSTREAM_HTTP_TIMEOUT_SECONDS", "Upstream HTTP timeout in seconds."),
    (
        "upstream_failure_threshold",
        int,
        3,
        "AGENT_BOM_GATEWAY_UPSTREAM_FAILURE_THRESHOLD",
        "Consecutive failures before opening the circuit.",
    ),
    (
        "upstream_circuit_cooldown_seconds",
        float,
        30.0,
        "AGENT_BOM_GATEWAY_UPSTREAM_CIRCUIT_COOLDOWN_SECONDS",
        "Seconds before retrying an open upstream circuit.",
    ),
)


def upstream_options(callback: Callable[..., None]) -> Callable[..., None]:
    """Add flags/env precedence and reuse the runtime's authoritative validator."""

    @wraps(callback)
    def wrapped(*args: Any, **kwargs: Any) -> None:
        from agent_bom.gateway_upstreams import UpstreamRegistry
        from agent_bom.runtime.gateway_settings import GatewaySettings, validate_gateway_security_settings

        options = {spec[0]: kwargs.pop(spec[0]) for spec in _OPTIONS}
        try:
            validate_gateway_security_settings(GatewaySettings(registry=UpstreamRegistry([]), policy={}, **options))
        except ValueError as exc:
            raise click.ClickException(sanitize_error(exc)) from exc
        callback(*args, upstream_options=options, **kwargs)

    for name, value_type, default, envvar, help_text in reversed(_OPTIONS):
        wrapped = click.option(
            "--" + name.replace("_", "-"),
            type=value_type,
            default=default,
            envvar=envvar,
            show_default=True,
            show_envvar=True,
            help=help_text,
        )(wrapped)
    return wrapped
