"""CLI glue for ``agent-bom proxy --url`` (remote MCP over Streamable HTTP)."""

from __future__ import annotations

import asyncio

import click

from agent_bom.runtime.injection_protection import SSE_UNSUPPORTED


def run_remote_proxy(
    url: str | None,
    policy: str | None,
    log_path: str | None,
    block_undeclared: bool,
    alert_webhook: str | None,
    mode: str | None,
    compat_endpoints: bool,
) -> int:
    if not url:
        raise click.UsageError("--compat-endpoints only applies with --url.")
    if (mode or "").lower() == "enforce":
        raise click.UsageError(SSE_UNSUPPORTED)
    from agent_bom.proxy import _proxy_sse_server

    return asyncio.run(
        _proxy_sse_server(
            url=url,
            policy_path=policy,
            log_path=log_path,
            block_undeclared=block_undeclared,
            alert_webhook=alert_webhook,
            compat_endpoints=compat_endpoints,
        )
    )
