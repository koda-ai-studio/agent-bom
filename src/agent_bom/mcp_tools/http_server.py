"""HTTP runner that leaves forwarded-source validation to the application."""

from __future__ import annotations

from typing import Any


def install_http_runner(server) -> None:
    original_run = server.run

    def run(transport="stdio", **kwargs):
        if transport not in {"streamable-http", "sse"}:
            return original_run(transport=transport, **kwargs)
        import uvicorn

        host = kwargs.pop("host", "127.0.0.1")
        port = kwargs.pop("port", 8000)
        builder = server.streamable_http_app if transport == "streamable-http" else server.sse_app
        app = builder(host=host, **kwargs)
        return uvicorn.run(
            app, host=host, port=port, log_level=server.settings.log_level.lower(), proxy_headers=False, limit_concurrency=500
        )

    server.run = run
    _install_auth_failure_gate(server)


def _install_auth_failure_gate(mcp: Any) -> None:
    """Keep source backoff outside the SDK's bearer/OAuth authentication."""
    from agent_bom.api.auth_failure_policy import AuthFailureMiddleware

    def wrap(builder):
        def build_app(*args: Any, **kwargs: Any) -> Any:
            app = builder(*args, **kwargs)
            app.add_middleware(AuthFailureMiddleware)
            return app

        return build_app

    for name in ("streamable_http_app", "sse_app"):
        setattr(mcp, name, wrap(getattr(mcp, name)))
