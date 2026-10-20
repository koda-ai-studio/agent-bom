"""Server commands — REST API, MCP server, combined serve."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import click

from agent_bom.cli._common import LISTEN_PORT_RANGE
from agent_bom.cli._demo_storage import demo_estate_default_persist as _demo_estate_default_persist
from agent_bom.cli._server_posture import (
    _DEV_API_KEY_PREFIX as _DEV_API_KEY_PREFIX,
)
from agent_bom.cli._server_posture import _api_auth_summary as _api_auth_summary
from agent_bom.cli._server_posture import _auth_summary as _auth_summary
from agent_bom.cli._server_posture import (
    _enforce_auth_defaults as _enforce_auth_defaults,
)
from agent_bom.cli._server_posture import (
    _enforce_control_plane_listener_posture as _enforce_control_plane_listener_posture,
)
from agent_bom.cli._server_posture import (
    _enforce_cors_posture as _enforce_cors_posture,
)
from agent_bom.cli._server_posture import (
    _enforce_database_role_posture as _enforce_database_role_posture,
)
from agent_bom.cli._server_posture import (
    _enforce_remote_mcp_auth_defaults as _enforce_remote_mcp_auth_defaults,
)
from agent_bom.cli._server_posture import (
    _enforce_writable_control_plane_state as _enforce_writable_control_plane_state,
)
from agent_bom.cli._server_posture import (
    _env_truthy as _env_truthy,
)
from agent_bom.cli._server_posture import (
    _fail_missing_optional_dependencies as _fail_missing_optional_dependencies,
)
from agent_bom.cli._server_posture import (
    _generate_dev_api_key as _generate_dev_api_key,
)
from agent_bom.cli._server_posture import (
    _is_loopback_host as _is_loopback_host,
)
from agent_bom.cli._server_posture import (
    _oidc_enabled as _oidc_enabled,
)
from agent_bom.cli._server_posture import (
    _require_optional_dependencies as _require_optional_dependencies,
)
from agent_bom.cli._server_posture import (
    _resolve_allow_unauthenticated as _resolve_allow_unauthenticated,
)
from agent_bom.cli._server_posture import (
    _saml_enabled as _saml_enabled,
)
from agent_bom.cli._server_posture import (
    _scim_bearer_enabled as _scim_bearer_enabled,
)
from agent_bom.cli._server_posture import (
    _should_auto_generate_dev_key as _should_auto_generate_dev_key,
)
from agent_bom.cli._server_posture import (
    _uvicorn_tls_kwargs as _uvicorn_tls_kwargs,
)
from agent_bom.core.settings import env_list, env_raw, env_str
from agent_bom.storage import state_home


def _configure_analytics_backend(
    *,
    analytics_backend: str | None,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
    analytics_max_queue: int,
) -> tuple[str, str | None]:
    """Resolve and export the requested analytics backend contract."""
    resolved_backend = (analytics_backend or "").strip().lower()
    resolved_url = (clickhouse_url or env_str("AGENT_BOM_CLICKHOUSE_URL")).strip() or None
    if resolved_backend in {"", "auto"}:
        resolved_backend = "clickhouse" if resolved_url else "disabled"
    if resolved_backend == "clickhouse" and not resolved_url:
        raise click.ClickException("ClickHouse analytics requires --clickhouse-url or AGENT_BOM_CLICKHOUSE_URL.")

    os.environ["AGENT_BOM_ANALYTICS_BACKEND"] = resolved_backend
    if resolved_url:
        os.environ["AGENT_BOM_CLICKHOUSE_URL"] = resolved_url
    elif resolved_backend == "disabled":
        os.environ.pop("AGENT_BOM_CLICKHOUSE_URL", None)

    os.environ["AGENT_BOM_CLICKHOUSE_BUFFERED"] = "1" if analytics_buffered else "0"
    os.environ["AGENT_BOM_CLICKHOUSE_FLUSH_INTERVAL"] = f"{analytics_flush_interval:.3f}"
    os.environ["AGENT_BOM_CLICKHOUSE_MAX_BATCH"] = str(max(1, analytics_max_batch))
    os.environ["AGENT_BOM_CLICKHOUSE_MAX_QUEUE"] = str(max(1, analytics_max_queue))
    return resolved_backend, resolved_url


def _emit_runtime_summary(title: str, rows: list[tuple[str, str]], *, err: bool = False) -> None:
    """Print a compact, aligned startup summary block with the BOM mark."""
    from agent_bom.output.brand_tokens import emit_cli_runtime_summary

    emit_cli_runtime_summary(title, rows, err=err)


_MCP_WORKFLOW_NAMES = (
    "quick-audit",
    "pre-install-check",
    "compliance-report",
    "fleet-audit",
    "incident-triage",
    "remediation-plan",
    "cloud-connection-review",
    "gateway-fleet-live-demo",
)


def _emit_mcp_stdio_workflow_splash(*, profile: str) -> None:
    """Emit a TTY-only MCP workflow hint without touching protocol stdout."""
    if not sys.stderr.isatty():
        return
    rows = [
        ("Transport", "stdio"),
        ("Workflows", f"{len(_MCP_WORKFLOW_NAMES)} prompts; see docs/MCP_SERVER.md"),
        ("Tools", f"{profile} profile"),
    ]
    _emit_runtime_summary("agent-bom MCP server", rows, err=True)


def _maybe_seed_local_connection_key(*, host: str, allow_insecure_no_auth: bool) -> str | None:
    """Auto-seed an at-rest connection encryption key for a local/no-auth stack.

    Fail-closed by construction. Fires only when *all* of these hold:

    - the deployment is clearly local: a loopback bind, or an explicit
      ``--allow-insecure-no-auth`` local-demo override;
    - the default ``env`` key provider is in effect (a managed provider owns its
      own key material and must never be shadowed by a local file);
    - no connection key is already configured (env, ``*_FILE``, or a prior seed);
    - the ``AGENT_BOM_NO_AUTO_CONNECTIONS_KEY`` opt-out is unset.

    Otherwise this is a no-op and connection creation keeps its existing
    behaviour (a 503 until the operator provides ``AGENT_BOM_CONNECTIONS_KEY``).

    The key is written beneath ``AGENT_BOM_STATE_DIR`` when set (otherwise
    ``~/.agent-bom/connections.key``) so local stacks can isolate all state.
    It survives restarts and previously-stored ciphertext stays decryptable. On success the
    process-local ``AGENT_BOM_CONNECTIONS_KEY_FILE`` is pointed at the file and
    the resolver cache is reset. Any failure degrades silently to the prior
    fail-closed behaviour rather than blocking boot.
    """
    if _env_truthy("AGENT_BOM_NO_AUTO_CONNECTIONS_KEY"):
        return None
    if not (_is_loopback_host(host) or allow_insecure_no_auth):
        return None
    from agent_bom.api.connection_crypto import (
        CONNECTIONS_KEY_ENV,
        CONNECTIONS_KEY_PROVIDER_ENV,
        connections_key_configured,
        reset_key_cache,
        seed_local_connection_key,
    )

    provider = env_str(CONNECTIONS_KEY_PROVIDER_ENV, "env").lower()
    if provider != "env":
        return None
    if connections_key_configured():
        return None
    try:
        state_dir = state_home.state_dir()
        path = seed_local_connection_key(state_dir)
    except Exception:  # noqa: BLE001 - never block boot; stay fail-closed on connect
        return None
    os.environ[f"{CONNECTIONS_KEY_ENV}_FILE"] = str(path)
    reset_key_cache()
    return str(path)


def _activate_demo_state_dir_or_fail() -> Path | None:
    """Pin demo-estate mode to its own data directory before any store opens."""
    from agent_bom.storage.state_home import activate_demo_state_dir

    try:
        return activate_demo_state_dir()
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


def _storage_summary(*, persist: str | None) -> str:
    """Describe the active API job storage mode."""
    if persist:
        return f"SQLite ({persist})"

    from agent_bom.api import stores
    from agent_bom.api.server import _backend_name

    # Lifespan preserves an injected store; the legacy api command also selects
    # its Postgres job store before printing this table. Never create a store
    # merely to describe it, or print a configured connection string.
    if stores._store is not None:
        backend = _backend_name(stores._store)
        return {"inmemory": "In-memory (ephemeral)", "sqlite": "SQLite", "postgres": "PostgreSQL", "snowflake": "Snowflake"}.get(
            backend, f"Custom ({backend})"
        )

    # Mirror the pending job-store selection in server._lifespan. Neptune's
    # graph-only branch currently leaves the lazy job store in memory.
    if env_raw("SNOWFLAKE_ACCOUNT"):
        return "Snowflake"
    if env_str("AGENT_BOM_GRAPH_BACKEND").lower() == "neptune":
        return "In-memory (ephemeral)"
    if env_raw("AGENT_BOM_POSTGRES_URL"):
        return "PostgreSQL"
    if env_raw("AGENT_BOM_DB"):
        return "SQLite"
    return "In-memory (ephemeral)"


def _analytics_summary_rows(
    *,
    resolved_backend: str,
    resolved_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
    analytics_max_queue: int,
) -> list[tuple[str, str]]:
    """Describe analytics mode in one or two aligned rows."""
    if resolved_backend != "clickhouse":
        return [("Analytics", "Disabled")]
    mode = "buffered" if analytics_buffered else "direct"
    return [
        (
            "Analytics",
            f"ClickHouse ({mode}, batch={max(1, analytics_max_batch)}, queue={max(1, analytics_max_queue)}, "
            f"flush={analytics_flush_interval:.2f}s)",
        ),
        ("Analytics URL", resolved_url or "(unset)"),
    ]


@click.command("serve")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to bind to (non-loopback requires --api-key / OIDC or --allow-insecure-no-auth).",
)
@click.option("--port", default=8422, show_default=True, type=LISTEN_PORT_RANGE, help="API server port")
@click.option(
    "--persist",
    default=None,
    metavar="DB_PATH",
    help=(
        "SQLite database for API jobs, the graph, and control-plane stores (sets AGENT_BOM_DB; "
        "for example ~/.agent-bom/control-plane.db). Other local state (assets, analytics, caches) "
        "stays under AGENT_BOM_STATE_DIR (default ~/.agent-bom)."
    ),
)
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help=(
        "Require API key auth (Bearer token or X-API-Key header). "
        "Other accepted auth paths: AGENT_BOM_OIDC_ISSUER (OIDC) and "
        "AGENT_BOM_SCIM_BEARER_TOKEN (SCIM bearer for IdP integration)."
    ),
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help=(
        "Allow unauthenticated non-loopback API exposure. Unsafe outside local development. "
        "Note: when AGENT_BOM_API_KEY / AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_SCIM_BEARER_TOKEN is also set, those auth paths still "
        "enforce; the flag emits a warning instead of bypassing them."
    ),
)
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option(
    "--no-ui",
    "no_ui",
    is_flag=True,
    default=False,
    help="Serve the REST API only; do not mount the bundled dashboard (REST-only mode, formerly `agent-bom api`).",
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
)
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
@click.option(
    "--analytics-backend",
    type=click.Choice(["auto", "disabled", "clickhouse"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Analytics backend for trend/event persistence.",
)
@click.option(
    "--clickhouse-url",
    default=None,
    envvar="AGENT_BOM_CLICKHOUSE_URL",
    metavar="URL",
    help="ClickHouse HTTP URL for analytics.",
)
@click.option(
    "--analytics-buffered/--no-analytics-buffered",
    default=True,
    show_default=True,
    help="Buffer ClickHouse analytics writes in a background thread.",
)
@click.option(
    "--analytics-flush-interval",
    default=1.0,
    show_default=True,
    type=float,
    metavar="SECONDS",
    help="Buffered ClickHouse flush interval.",
)
@click.option(
    "--analytics-max-batch",
    default=200,
    show_default=True,
    type=int,
    metavar="ROWS",
    help="Maximum rows to flush per ClickHouse batch.",
)
@click.option(
    "--analytics-max-queue",
    default=10_000,
    show_default=True,
    type=int,
    metavar="ENTRIES",
    help="Maximum buffered ClickHouse entries before oldest evidence is dropped.",
)
@click.option(
    "--demo-estate",
    is_flag=True,
    default=False,
    envvar="AGENT_BOM_DEMO_ESTATE",
    help="Seed a labeled demo graph and curated offline findings on first API start.",
)
def serve_cmd(
    host: str,
    port: int,
    persist: Optional[str],
    cors_allow_all: bool,
    api_key: str | None,
    allow_insecure_no_auth: bool,
    reload: bool,
    no_ui: bool,
    log_level: str,
    log_json: bool,
    analytics_backend: str,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
    analytics_max_queue: int,
    demo_estate: bool,
):
    """Start the API server and serve the dashboard when UI assets are built.

    \b
    Requires:  pip install 'agent-bom[ui]'
               make build-ui   (for the bundled dashboard)

    \b
    Usage:
      Local only:
        agent-bom serve
      Remote with auth:
        agent-bom serve --host 0.0.0.0 --api-key <key>
      Persistent jobs:
        agent-bom serve --persist ~/.agent-bom/control-plane.db --port 8422
    """
    from agent_bom.logging_config import api_log_config, setup_logging

    setup_logging(level=log_level, json_output=log_json)

    _require_optional_dependencies(
        "agent-bom serve",
        "ui",
        {"FastAPI": "fastapi", "Uvicorn": "uvicorn"},
    )

    if demo_estate:
        os.environ["AGENT_BOM_DEMO_ESTATE"] = "1"
    persist_path = str(Path(persist).expanduser().resolve()) if persist else None
    if persist_path:
        os.environ["AGENT_BOM_DB"] = persist_path
    demo_state_dir = _activate_demo_state_dir_or_fail()
    persist_path = persist_path or _demo_estate_default_persist(demo_state_dir)
    if cors_allow_all:
        os.environ["AGENT_BOM_CORS_ALL"] = "1"
    # REST-only mode: signal the API app (imported below) to skip mounting the
    # dashboard. Set before the first `agent_bom.api.server` import.
    if no_ui:
        os.environ["AGENT_BOM_NO_UI"] = "1"
    resolved_backend, resolved_url = _configure_analytics_backend(
        analytics_backend=analytics_backend,
        clickhouse_url=clickhouse_url,
        analytics_buffered=analytics_buffered,
        analytics_flush_interval=analytics_flush_interval,
        analytics_max_batch=analytics_max_batch,
        analytics_max_queue=analytics_max_queue,
    )

    _enforce_cors_posture(host, cors_allow_all)
    _enforce_auth_defaults("serve", host, api_key, allow_insecure_no_auth)
    _enforce_control_plane_listener_posture(host)
    _enforce_database_role_posture("serve")
    _enforce_writable_control_plane_state("serve")
    tls_kwargs = _uvicorn_tls_kwargs()

    seeded_connection_key = _maybe_seed_local_connection_key(host=host, allow_insecure_no_auth=allow_insecure_no_auth)

    # Zero-config loopback: when bound to loopback with no auth configured and no
    # opt-out, mint an ephemeral dev key so the dashboard loads without flags.
    # Non-loopback binds never reach here unauthenticated (see the gate above),
    # so this can only ever fire on loopback.
    dev_api_key = (
        _generate_dev_api_key()
        if _should_auto_generate_dev_key(host=host, api_key=api_key, allow_insecure_no_auth=allow_insecure_no_auth)
        else None
    )

    from agent_bom.api.server import configure_api, set_dev_api_key, set_job_store

    set_dev_api_key(dev_api_key)
    configure_api(
        cors_allow_all=cors_allow_all,
        api_key=api_key or dev_api_key,
        allow_unauthenticated=allow_insecure_no_auth,
        listener_host=host,
    )
    if persist_path:
        # Do not rely only on the server module's first-import environment
        # selection. Embedded callers and tests can import the app before the
        # CLI command runs; an explicit flag must still select durable jobs.
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist_path))

    _ui_dist = Path(__file__).resolve().parents[1] / "ui_dist"
    rows = [
        ("API", f"http://{host}:{port}"),
        ("Docs", f"http://{host}:{port}/docs"),
        (
            "Dashboard",
            "Disabled (--no-ui, REST only)"
            if no_ui
            else (f"http://{host}:{port}" if (_ui_dist / "index.html").exists() else "Not bundled (run: make build-ui)"),
        ),
        (
            "Auth",
            _api_auth_summary(
                host=host,
                api_key=api_key,
                oidc_enabled=_oidc_enabled(),
                allow_unauthenticated=_resolve_allow_unauthenticated(allow_insecure_no_auth),
                dev_api_key=dev_api_key,
            ),
        ),
        ("TLS", "app-native mTLS" if tls_kwargs.get("ssl_ca_certs") else ("server TLS" if tls_kwargs else "delegated/none")),
        ("Storage", _storage_summary(persist=persist_path)),
        *([("Demo data", str(demo_state_dir))] if demo_state_dir else []),
        *_analytics_summary_rows(
            resolved_backend=resolved_backend,
            resolved_url=resolved_url,
            analytics_buffered=analytics_buffered,
            analytics_flush_interval=analytics_flush_interval,
            analytics_max_batch=analytics_max_batch,
            analytics_max_queue=analytics_max_queue,
        ),
    ]
    _emit_runtime_summary("agent-bom serve", rows)
    if seeded_connection_key:
        click.echo(
            f"  Connection secrets: auto-sealed at rest with a locally generated key ({seeded_connection_key}).\n"
            "  Set AGENT_BOM_CONNECTIONS_KEY / _FILE or a managed provider to bring your own; "
            "AGENT_BOM_NO_AUTO_CONNECTIONS_KEY=1 disables auto-seeding.\n"
        )
    if dev_api_key:
        click.secho(
            f"  Dev API key (loopback only): {dev_api_key}",
            fg="cyan",
            bold=True,
        )
        click.echo(
            "  The local dashboard uses this automatically. Send it as "
            "'Authorization: Bearer <key>' for CLI/API calls.\n"
            "  Ephemeral (per-process, not saved). Set AGENT_BOM_NO_AUTO_DEV_KEY=1 to disable.\n"
        )

    try:
        import uvicorn as _uvicorn
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom serve", "ui", ["Uvicorn"])
    _uvicorn.run(
        "agent_bom.api.server:app",
        log_config=api_log_config(_uvicorn.config.LOGGING_CONFIG),
        host=host,
        port=port,
        reload=reload,
        timeout_keep_alive=5,
        limit_concurrency=500,
        **tls_kwargs,
    )


@click.command("api")
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to bind to (non-loopback requires --api-key / OIDC or --allow-insecure-no-auth).",
)
@click.option("--port", default=8422, show_default=True, type=LISTEN_PORT_RANGE, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--workers", default=1, show_default=True, help="Number of worker processes")
@click.option("--cors-origins", default=None, metavar="ORIGINS", help="Comma-separated CORS origins (default: localhost:3000).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key",
    default=None,
    envvar="AGENT_BOM_API_KEY",
    metavar="KEY",
    help=(
        "Require API key auth (Bearer token or X-API-Key header). "
        "Other accepted auth paths: AGENT_BOM_OIDC_ISSUER (OIDC) and "
        "AGENT_BOM_SCIM_BEARER_TOKEN (SCIM bearer for IdP integration)."
    ),
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help=(
        "Allow unauthenticated non-loopback API exposure. Unsafe outside local development. "
        "Note: when AGENT_BOM_API_KEY / AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_SCIM_BEARER_TOKEN is also set, those auth paths still "
        "enforce; the flag emits a warning instead of bypassing them."
    ),
)
@click.option(
    "--rate-limit",
    "rate_limit_rpm",
    default=600,
    show_default=True,
    type=click.IntRange(1, 60_000),
    metavar="RPM",
    help="Rate limit for scan endpoints (requests/minute per IP).",
)
@click.option(
    "--persist",
    default=None,
    metavar="DB_PATH",
    help=(
        "SQLite database for API jobs, the graph, and control-plane stores (sets AGENT_BOM_DB; "
        "e.g. --persist jobs.db). Other local state (assets, analytics, caches) stays under "
        "AGENT_BOM_STATE_DIR (default ~/.agent-bom)."
    ),
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Log verbosity level.",
)
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs (for log aggregation pipelines).")
@click.option(
    "--analytics-backend",
    type=click.Choice(["auto", "disabled", "clickhouse"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Analytics backend for trend/event persistence.",
)
@click.option(
    "--clickhouse-url",
    default=None,
    envvar="AGENT_BOM_CLICKHOUSE_URL",
    metavar="URL",
    help="ClickHouse HTTP URL for analytics.",
)
@click.option(
    "--analytics-buffered/--no-analytics-buffered",
    default=True,
    show_default=True,
    help="Buffer ClickHouse analytics writes in a background thread.",
)
@click.option(
    "--analytics-flush-interval",
    default=1.0,
    show_default=True,
    type=float,
    metavar="SECONDS",
    help="Buffered ClickHouse flush interval.",
)
@click.option(
    "--analytics-max-batch",
    default=200,
    show_default=True,
    type=int,
    metavar="ROWS",
    help="Maximum rows to flush per ClickHouse batch.",
)
@click.option(
    "--analytics-max-queue",
    default=10_000,
    show_default=True,
    type=int,
    metavar="ENTRIES",
    help="Maximum buffered ClickHouse entries before oldest evidence is dropped.",
)
@click.option(
    "--demo-estate",
    is_flag=True,
    default=False,
    envvar="AGENT_BOM_DEMO_ESTATE",
    help="Seed a labeled demo graph and curated offline findings on first API start.",
)
def api_cmd(
    host: str,
    port: int,
    reload: bool,
    workers: int,
    cors_origins: str | None,
    cors_allow_all: bool,
    api_key: str | None,
    allow_insecure_no_auth: bool,
    rate_limit_rpm: int,
    persist: str | None,
    log_level: str,
    log_json: bool,
    analytics_backend: str,
    clickhouse_url: str | None,
    analytics_buffered: bool,
    analytics_flush_interval: float,
    analytics_max_batch: int,
    analytics_max_queue: int,
    demo_estate: bool,
):
    """Start the agent-bom REST API server.

    \b
    Requires:  pip install 'agent-bom[api]'

    \b
    Endpoints:
      GET  /docs                   Interactive API docs (Swagger UI)
      GET  /health                 Liveness probe
      GET  /version                Version info
      POST /v1/scan                Start a scan (async, returns job_id)
      GET  /v1/scan/{job_id}       Poll status + results
      GET  /v1/scan/{job_id}/stream  SSE real-time progress
      GET  /v1/agents              Quick agent discovery (no CVE scan)
      GET  /v1/jobs                List all scan jobs

    \b
    Usage:
      Local only:
        agent-bom api
      Remote with auth:
        agent-bom api --host 0.0.0.0 --api-key <key>
      Custom port / dev reload:
        agent-bom api --port 9000
        agent-bom api --reload
    """
    from agent_bom.logging_config import api_log_config, setup_logging

    setup_logging(level=log_level, json_output=log_json)

    _require_optional_dependencies(
        "agent-bom api",
        "api",
        {"FastAPI": "fastapi", "Uvicorn": "uvicorn"},
    )

    if demo_estate:
        os.environ["AGENT_BOM_DEMO_ESTATE"] = "1"
    if persist:
        persist = str(Path(persist).expanduser().resolve())
        os.environ["AGENT_BOM_DB"] = persist
    demo_state_dir = _activate_demo_state_dir_or_fail()
    persist = persist or _demo_estate_default_persist(demo_state_dir)

    try:
        import uvicorn
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom api", "api", ["Uvicorn"])

    resolved_backend, resolved_url = _configure_analytics_backend(
        analytics_backend=analytics_backend,
        clickhouse_url=clickhouse_url,
        analytics_buffered=analytics_buffered,
        analytics_flush_interval=analytics_flush_interval,
        analytics_max_batch=analytics_max_batch,
        analytics_max_queue=analytics_max_queue,
    )

    from agent_bom import __version__ as _ver
    from agent_bom.api.server import configure_api, set_job_store

    _enforce_cors_posture(host, cors_allow_all)
    _enforce_auth_defaults("api", host, api_key, allow_insecure_no_auth)
    _enforce_control_plane_listener_posture(host)
    _enforce_database_role_posture("api")
    _enforce_writable_control_plane_state("api")
    tls_kwargs = _uvicorn_tls_kwargs()

    seeded_connection_key = _maybe_seed_local_connection_key(host=host, allow_insecure_no_auth=allow_insecure_no_auth)

    origins = cors_origins.split(",") if cors_origins else None
    configure_api(
        cors_origins=origins,
        cors_allow_all=cors_allow_all,
        api_key=api_key,
        rate_limit_rpm=rate_limit_rpm,
        allow_unauthenticated=allow_insecure_no_auth,
        listener_host=host,
    )

    pg_url = env_raw("AGENT_BOM_POSTGRES_URL")
    if pg_url and not persist:
        # Postgres takes priority when no explicit --persist flag
        from agent_bom.api.postgres_store import PostgresJobStore

        set_job_store(PostgresJobStore())
    elif persist:
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist))

    rows = [
        ("Version", _ver),
        ("Bind", f"http://{host}:{port}"),
        ("Docs", f"http://{host}:{port}/docs"),
        (
            "Auth",
            _api_auth_summary(
                host=host,
                api_key=api_key,
                oidc_enabled=_oidc_enabled(),
                allow_unauthenticated=_resolve_allow_unauthenticated(allow_insecure_no_auth),
            ),
        ),
        ("TLS", "app-native mTLS" if tls_kwargs.get("ssl_ca_certs") else ("server TLS" if tls_kwargs else "delegated/none")),
        ("Storage", _storage_summary(persist=persist)),
        *([("Demo data", str(demo_state_dir))] if demo_state_dir else []),
        *_analytics_summary_rows(
            resolved_backend=resolved_backend,
            resolved_url=resolved_url,
            analytics_buffered=analytics_buffered,
            analytics_flush_interval=analytics_flush_interval,
            analytics_max_batch=analytics_max_batch,
            analytics_max_queue=analytics_max_queue,
        ),
    ]
    _emit_runtime_summary("agent-bom API", rows)
    if seeded_connection_key:
        click.echo(
            f"  Connection secrets: auto-sealed at rest with a locally generated key ({seeded_connection_key}).\n"
            "  Set AGENT_BOM_CONNECTIONS_KEY / _FILE or a managed provider to bring your own; "
            "AGENT_BOM_NO_AUTO_CONNECTIONS_KEY=1 disables auto-seeding.\n"
        )

    uvicorn.run(
        "agent_bom.api.server:app",
        log_config=api_log_config(uvicorn.config.LOGGING_CONFIG),
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level=log_level.lower(),
        # Bound idle connections and concurrent requests.
        timeout_keep_alive=5,
        # Hard cap on concurrent in-flight requests; prevents thread/FD exhaustion
        # under a slow-connection flood. 500 ≫ any realistic single-server load.
        limit_concurrency=500,
        **tls_kwargs,
    )


@click.command("mcp-server")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    show_default=True,
    help="MCP transport protocol.",
)
@click.option("--port", default=8423, show_default=True, type=LISTEN_PORT_RANGE, help="Port for HTTP/SSE transport.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host for HTTP/SSE transport.")
@click.option(
    "--profile",
    type=click.Choice(["scan", "graph", "cloud", "runtime", "audit", "guided", "full"]),
    default="scan",
    show_default=True,
    help="Task profile. Scan exposes 8 tools; full explicitly enables the complete compatibility catalog.",
)
@click.option(
    "--bearer-token",
    default=None,
    envvar="AGENT_BOM_MCP_BEARER_TOKEN",
    metavar="TOKEN",
    help="Require Bearer token auth for SSE / Streamable HTTP transports.",
)
@click.option(
    "--allow-insecure-no-auth",
    is_flag=True,
    default=False,
    help="Allow unauthenticated non-loopback SSE / HTTP exposure. Unsafe outside local development.",
)
@click.option(
    "--workspace-root",
    "workspace_roots",
    multiple=True,
    type=click.Path(file_okay=False, resolve_path=True),
    help=(
        "Extra directory that path arguments may resolve into, in addition to HOME "
        "(e.g. /workspaces in a devcontainer). Repeatable; merged with AGENT_BOM_MCP_WORKSPACE_ROOTS."
    ),
)
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def mcp_server_cmd(
    transport: str,
    port: int,
    host: str,
    profile: str,
    bearer_token: str | None,
    allow_insecure_no_auth: bool,
    workspace_roots: tuple[str, ...],
    log_level: str,
    log_json: bool,
):
    """Start agent-bom as an MCP server.

    \b
    The MCP SDK is included in the standard agent-bom install.

    \b
    Default: 8 scan, package-check, exposure, compliance and remediation tools.
    Start with quick-audit, pre-install-check or remediation-plan prompts.
    Read profiles://catalog for task profiles without loading all tool schemas.

    \b
    Select graph, cloud, runtime or audit for specialized work. Reconnect after
    changing profiles. Use --profile full for existing workflows needing the
    complete catalog, or --profile guided. Profiles do not grant authorization; see docs/MCP_SERVER.md.

    \b
    Usage:
      Local stdio: agent-bom mcp server
      Remote with bearer auth:
        Provision the token and its absolute timezone-aware expiry within one hour.
        Set AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT through your secure environment.
        agent-bom mcp server --transport sse --bearer-token <token>
        agent-bom mcp server --transport streamable-http --bearer-token <token>

    \b
    Claude Desktop config (mcpServers):
      macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
      Linux: ~/.config/Claude/claude_desktop_config.json
      Windows: %APPDATA%/Claude/claude_desktop_config.json
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    if workspace_roots:
        existing = list(env_list("AGENT_BOM_MCP_WORKSPACE_ROOTS", sep=os.pathsep))
        os.environ["AGENT_BOM_MCP_WORKSPACE_ROOTS"] = os.pathsep.join([*existing, *workspace_roots])

    _require_optional_dependencies(
        "agent-bom mcp server",
        "mcp-server",
        {"MCP SDK": "mcp"},
    )

    try:
        from agent_bom.mcp_server import create_mcp_server
    except ImportError:
        _fail_missing_optional_dependencies("agent-bom mcp server", "mcp-server", ["MCP SDK"])

    if transport in ("sse", "streamable-http"):
        _enforce_remote_mcp_auth_defaults(host, bearer_token, allow_insecure_no_auth)
        # Signal a remotely-bound (internet-reachable) MCP transport so repo
        # scans fail closed unless an explicit host allowlist is configured.
        if not _is_loopback_host(host):
            os.environ["AGENT_BOM_MCP_REMOTE_BIND"] = "1"

    from agent_bom.mcp_tools.oauth import oauth_configured

    # Stdio uses its parent process boundary; inherited HTTP credentials do not
    # activate a token verifier for a local session.
    try:
        server = create_mcp_server(
            host=host,
            port=port,
            bearer_token=bearer_token if transport in ("sse", "streamable-http") else None,
            profile=profile,
            oauth_enabled=transport in ("sse", "streamable-http") and oauth_configured(),
        )
    except ValueError as exc:
        from agent_bom.security import sanitize_error

        raise click.ClickException(sanitize_error(exc)) from exc

    if transport in ("sse", "streamable-http"):
        from agent_bom import __version__ as _ver

        rows = [
            ("Version", _ver),
            ("Transport", transport),
            ("Profile", profile),
            ("Bind", f"http://{host}:{port}"),
            ("Workflows", f"{len(_MCP_WORKFLOW_NAMES)} prompts; see docs/MCP_SERVER.md"),
            (
                "Auth",
                _auth_summary(
                    host=host,
                    bearer_token=bearer_token,
                    allow_insecure_no_auth=allow_insecure_no_auth,
                    mcp_remote=True,
                    oidc_enabled=oauth_configured(),
                ),
            ),
        ]
        _emit_runtime_summary("agent-bom MCP server", rows, err=True)
        server.run(transport=transport, host=host, port=port)
    else:
        if bearer_token:
            click.echo("  Warning:   --bearer-token applies only to SSE / Streamable HTTP transports", err=True)
        _emit_mcp_stdio_workflow_splash(profile=profile)
        server.run(transport="stdio")
