"""Safe bundled dashboard paths and static route mounting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from agent_bom.api.dashboard_not_found import DASHBOARD_CSP_META_RE
from agent_bom.api.middleware import register_dashboard_spa_routes
from agent_bom.api.routes.enterprise_routes._session_helpers import _maybe_attach_dev_session_cookie
from agent_bom.core.settings import env_raw

_DASHBOARD_CSP_META_RE = DASHBOARD_CSP_META_RE


@dataclass(frozen=True)
class _DashboardFile:
    path: Path
    relative_path: str


def _validated_dashboard_file(ui_dist: Path, relative_path: str) -> _DashboardFile | None:
    ui_root = ui_dist.resolve()
    raw_path = relative_path.strip()
    if not raw_path:
        return None
    if Path(raw_path).is_absolute():
        return None
    rel = raw_path.strip("/")
    if not rel:
        return None
    rel_path = Path(rel)
    candidate = (ui_root / rel_path).resolve()
    try:
        normalized = candidate.relative_to(ui_root).as_posix()
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return _DashboardFile(path=candidate, relative_path=normalized)


def _dashboard_html_response(dashboard_file: _DashboardFile) -> HTMLResponse:
    from fastapi.responses import HTMLResponse

    try:
        html = dashboard_file.path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        html = dashboard_file.path.read_text(encoding="utf-8", errors="replace")
    return HTMLResponse(_DASHBOARD_CSP_META_RE.sub("", html))


def mount_dashboard(application: FastAPI, ui_dist: Path) -> None:
    """Mount pre-built Next.js dashboard if ui_dist/ exists in the package."""
    from fastapi import HTTPException as _HTTPException

    # REST-only mode (`serve --no-ui` / legacy `api`): never mount the dashboard.
    if env_raw("AGENT_BOM_NO_UI"):
        return

    if not ui_dist.is_dir() or not (ui_dist / "index.html").exists():
        from agent_bom.api.dashboard_missing import mount_missing_dashboard

        mount_missing_dashboard(application)
        return

    from starlette.responses import FileResponse

    next_static = ui_dist / "_next"
    if next_static.is_dir():  # hashed JS/CSS build assets
        from agent_bom.api.dashboard_assets import InMemoryBuildAssets

        application.mount("/_next", InMemoryBuildAssets(directory=str(next_static)), name="next-static")

    # Pre-build a bounded static file map at startup so request paths are
    # resolved only as lookup keys.
    _static_file_map: dict[str, _DashboardFile] = {}
    for _f in ui_dist.rglob("*"):
        if not _f.is_file():
            continue
        relative = _f.relative_to(ui_dist).as_posix()
        if relative.startswith("_next"):
            continue
        dashboard_file = _validated_dashboard_file(ui_dist, relative)
        if dashboard_file is not None:
            _static_file_map[dashboard_file.relative_path] = dashboard_file
    _index_html = _validated_dashboard_file(ui_dist, "index.html")
    if _index_html is None:
        return

    # Auth's public-SPA allowlist is derived from exactly the files the
    # catch-all below can resolve, so a cold deep-link to a real page never
    # 401s and a route the SPA does not serve is never allowlisted.
    register_dashboard_spa_routes(_static_file_map)

    # SPA catch-all for client-side routing
    @application.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def _spa_catch_all(path: str, request: Request) -> Response:
        # Skip API and docs paths
        if path.startswith(("v1/", "docs", "redoc", "openapi.json", "health", "version", "readyz", "metrics")):
            raise _HTTPException(status_code=404)
        # Look up the pre-resolved path — user input is only a dict key,
        # never used in any filesystem operation (no path-injection risk).
        normalized_path = path.strip("/")
        resolved = (
            _static_file_map.get(path)
            or (normalized_path and _static_file_map.get(f"{normalized_path}.html"))
            or (normalized_path and _static_file_map.get(f"{normalized_path}/index.html"))
        )
        if resolved:
            if path.lower().endswith(".html") or resolved.relative_path.lower().endswith(".html"):
                html_response = _dashboard_html_response(resolved)
                _maybe_attach_dev_session_cookie(html_response, request)
                return html_response
            return FileResponse(resolved.path)
        # SPA fallback — serve index.html for client-side routing
        fallback_response = _dashboard_html_response(_index_html)
        _maybe_attach_dev_session_cookie(fallback_response, request)
        return fallback_response
