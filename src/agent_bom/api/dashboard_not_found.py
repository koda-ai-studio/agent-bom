"""The dashboard's own 404 page for unknown browser paths outside the API.

An unknown ``GET``/``HEAD`` path like ``/no-such-page`` is a browser
navigation, so it gets the bundled ``404.html`` (or a plain 404 when no
dashboard is bundled) instead of the JSON "operation has no authorization
policy" refusal meant for API callers. ``/v1`` paths and writes keep that
fail-closed answer.
"""

from __future__ import annotations

import re
from pathlib import Path

from starlette.responses import HTMLResponse, PlainTextResponse, Response

from agent_bom.core.settings import env_raw

DASHBOARD_CSP_META_RE = re.compile(
    r"<meta\s+[^>]*(?:http-equiv|httpEquiv)=[\"']Content-Security-Policy[\"'][^>]*>",
    re.IGNORECASE,
)


def dashboard_dist_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "ui_dist"


def non_api_not_found(method: str, path: str) -> Response | None:
    """The 404 response for an unknown browser path, or ``None`` when the API answer applies."""
    if method not in {"GET", "HEAD"} or path == "/v1" or path.startswith("/v1/"):
        return None
    page = dashboard_dist_dir() / "404.html"
    if not env_raw("AGENT_BOM_NO_UI") and page.is_file():
        html = page.read_text(encoding="utf-8", errors="replace")
        return HTMLResponse(DASHBOARD_CSP_META_RE.sub("", html), status_code=404)
    return PlainTextResponse("Not Found", status_code=404)
