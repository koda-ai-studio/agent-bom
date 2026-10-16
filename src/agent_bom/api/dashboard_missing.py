"""Bounded public diagnostics for known dashboard entry points without a bundle."""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from agent_bom.api.middleware import register_dashboard_spa_routes

_MISSING_UI = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard not bundled — agent-bom</title>
<style>:root{color-scheme:light dark}body{font:1rem/1.6 system-ui;margin:2rem auto;padding:0 1rem;max-width:48rem}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:1rem;border:1px solid #888;border-radius:.5rem}
a{color:LinkText}</style></head><body>
<main><h1>Dashboard not bundled</h1>
<p>This installation has the API but does not contain the built dashboard assets.</p>
<p>In a fresh virtual environment, install the published package:</p>
<pre>python -m pip install 'agent-bom[api]'
agent-bom serve</pre>
<p>For a source checkout, follow the dashboard build instructions in the
<a href="https://github.com/koda-ai-studio/agent-bom/blob/main/ui/README.md">dashboard development guide</a>.</p>
<p><a href="/docs">Open API documentation</a>. API authentication remains required under the configured auth mode.</p>
</main></body></html>"""


def mount_missing_dashboard(application: FastAPI) -> None:
    """Expose exact GET/HEAD diagnostic routes; no SPA prefix or API exemption."""
    paths = ("graph", "security-graph")
    # Extensionless keys register exact public paths without establishing SPA
    # first-segment routing. Nested paths and all API operations stay protected.
    register_dashboard_spa_routes(paths)

    async def unavailable() -> HTMLResponse:
        return HTMLResponse(_MISSING_UI, status_code=503, headers={"Cache-Control": "no-store"})

    for path in paths:
        application.add_api_route(f"/{path}", unavailable, methods=["GET", "HEAD"], include_in_schema=False)
