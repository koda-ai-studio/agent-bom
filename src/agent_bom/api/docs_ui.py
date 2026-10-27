"""Pinned documentation assets with SRI and per-response script nonces."""

from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from starlette.responses import HTMLResponse

_CDN = "https://cdn.jsdelivr.net/npm/"
_SWAGGER_JS = _CDN + "swagger-ui-dist@5.34.0/swagger-ui-bundle.js"
_SWAGGER_CSS = _CDN + "swagger-ui-dist@5.34.0/swagger-ui.css"
_REDOC_JS = _CDN + "redoc@2.5.4/bundles/redoc.standalone.js"
_ASSET_INTEGRITY = {
    _SWAGGER_JS: "sha384-9Td7MKiIr2S83E1kZyyVi8KdJw/S8CpAvu0llLyMeg0xq/hDGiZJfVn0fV4llCmK",
    _SWAGGER_CSS: "sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF",
    _REDOC_JS: "sha384-w447zOpYfw/1Tv/5AK9NfHTlQIqE3RVR6KY62jCyy9zNDgO64cMwGGP1Fj0zJVf5",
}


def docs_csp(nonce: str) -> str:
    return (
        f"default-src 'self'; script-src 'nonce-{nonce}'; script-src-attr 'none'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; font-src 'self' data:; worker-src 'self' blob:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )


def _secure_html(response: HTMLResponse, request: Request) -> HTMLResponse:
    nonce = secrets.token_urlsafe(24)
    request.state.docs_nonce = nonce
    html = bytes(response.body).decode()
    for url, integrity in _ASSET_INTEGRITY.items():
        html = html.replace(f'"{url}"', f'"{url}" integrity="{integrity}" crossorigin="anonymous"')
    html = html.replace("<script", f'<script nonce="{nonce}"')
    return HTMLResponse(html, headers={"Content-Security-Policy": docs_csp(nonce)})


def configure_docs(app: FastAPI, *, disabled: bool) -> None:
    """Replace default floating CDN pages without changing their public routes."""
    if disabled:
        return

    @app.get("/docs", include_in_schema=False)
    async def swagger(request: Request) -> HTMLResponse:
        prefix = quote(request.scope.get("root_path", "").rstrip("/"), safe="/")
        response = get_swagger_ui_html(
            openapi_url=prefix + "/openapi.json",
            title=app.title + " - Swagger UI",
            swagger_js_url=_SWAGGER_JS,
            swagger_css_url=_SWAGGER_CSS,
            swagger_favicon_url=prefix + "/brand/mark.svg",
        )
        return _secure_html(response, request)

    @app.get("/redoc", include_in_schema=False)
    async def redoc(request: Request) -> HTMLResponse:
        prefix = quote(request.scope.get("root_path", "").rstrip("/"), safe="/")
        response = get_redoc_html(
            openapi_url=prefix + "/openapi.json",
            title=app.title + " - ReDoc",
            redoc_js_url=_REDOC_JS,
            redoc_favicon_url=prefix + "/brand/mark.svg",
            with_google_fonts=False,
        )
        return _secure_html(response, request)
