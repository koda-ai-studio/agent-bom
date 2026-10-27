"""agent-bom FastAPI server.

Start with:
    agent-bom api                      # default: http://localhost:8422
    agent-bom api --host 0.0.0.0 --port 8422

Core infrastructure: lifespan, middleware, CORS, meta routes (/, /health, /version),
dashboard mounting. All domain routes live in api/routes/ sub-modules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from agent_bom import __version__
from agent_bom import config as _config
from agent_bom.api import host_guard as _host_guard
from agent_bom.api import stores as _stores
from agent_bom.api.audit_log import warn_if_ephemeral_hmac_key
from agent_bom.api.auth import Role, get_key_store
from agent_bom.api.dev_auth_state import get_dev_api_key as get_dev_api_key
from agent_bom.api.dev_auth_state import get_dev_api_role as get_dev_api_role
from agent_bom.api.dev_auth_state import set_dev_api_key as set_dev_api_key
from agent_bom.api.docs_ui import configure_docs
from agent_bom.api.error_envelope import ERROR_RESPONSES, install_error_envelope
from agent_bom.api.experimental_gate import ExperimentalFeatureHealth, SystemHealthResponse
from agent_bom.api.foreground_activity import ForegroundActivityMiddleware
from agent_bom.api.middleware import (
    DEFAULT_SCAN_RATE_LIMIT_RPM,
    MAX_RATE_LIMIT_RPM,
    APIKeyMiddleware,
    GlobalRateLimitMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
    global_ip_rate_limit_rpm,
)

# ─── Extracted modules ────────────────────────────────────────────────────────
from agent_bom.api.models import (  # noqa: F401 — legacy model imports
    AnalyticsHealth,
    EntitlementHealth,
    HealthResponse,
    JobStatus,
    PostgresPortabilityHealth,
    PublicHealthResponse,
    ScanJob,  # noqa: F401 — re-exported for legacy store imports
    ScanRequest,
    StepStatus,  # noqa: F401 — re-exported for tests
    StorageHealth,
    TracingHealth,
    VersionInfo,
)
from agent_bom.api.operator_keys import parse_env_api_keys, seed_operator_keys
from agent_bom.api.route_warmup import start_route_warmup
from agent_bom.api.routes.enterprise_routes._session_helpers import _maybe_attach_dev_session_cookie as _maybe_attach_dev_session_cookie
from agent_bom.api.scan_snapshot_store import expire_jobs_and_snapshots
from agent_bom.api.storage.analytics import peek_analytics_store
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.stores import (  # noqa: F401 — legacy store injection hooks
    _get_credential_ref_store,
    _get_schedule_store,
    _get_source_store,
    _get_store,
    _jobs,
    _jobs_get,  # noqa: F401 — re-exported for tests
    _jobs_lock,
    _jobs_pop,  # noqa: F401 — re-exported for tests
    _jobs_put,  # noqa: F401 — re-exported for tests
    set_analytics_store,
    set_credential_ref_store,
    set_exception_store,
    set_fleet_store,
    set_graph_store,
    set_policy_store,
    set_schedule_store,
    set_source_store,
    set_trend_store,
)
from agent_bom.api.stores import (  # noqa: F401 — legacy store injection hooks
    set_job_store as set_job_store,
)
from agent_bom.api.tracing import configure_otel_tracing, get_tracing_health
from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS
from agent_bom.config import resolved_cors_origins_raw
from agent_bom.core.experimental import feature_status
from agent_bom.core.settings import env_flag as _env_truthy
from agent_bom.demo_estate import boot_seed as _demo_boot_seed
from agent_bom.output.brand_tokens import POSITIONING_META, PRODUCT_NAME, TAGLINE_CHAIN
from agent_bom.storage import state_home as _state_home
from agent_bom.storage.tiers import preflight_storage_backends

_logger = logging.getLogger(__name__)

# Demo estate mode must resolve every default local store under its own data
# directory. Pin it before anything below lazily opens a store; this covers
# ``uvicorn agent_bom.api.server:app`` and multi-worker re-imports as well as
# the CLI, which activates it earlier.
_state_home.activate_demo_state_dir()
# ─── Dependency check ─────────────────────────────────────────────────────────


def _api_extra_import_error_message(exc: ImportError) -> str:
    missing = getattr(exc, "name", None)
    missing_line = f"\nMissing import: {missing!r}" if missing else ""
    return (
        "agent-bom API could not import its runtime dependencies."
        f"{missing_line}\n"
        "Install with:  pip install 'agent-bom[api]'\n"
        "If those packages are already installed, verify that `agent-bom api` is running in the same Python "
        "environment that contains fastapi, uvicorn, sse-starlette, pydantic, and starlette."
    )


try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, RedirectResponse, Response
    from pydantic import BaseModel  # noqa: F401 — presence check for [api] extra
    from starlette.middleware import Middleware
    from starlette.middleware.gzip import GZipMiddleware
except ImportError as exc:  # pragma: no cover
    raise ImportError(_api_extra_import_error_message(exc)) from exc

if TYPE_CHECKING:
    import datetime as _datetime


# ─── App ──────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager  # noqa: E402

# Imported after the optional API dependency diagnostic; legacy names remain available.
from agent_bom.api.server_dashboard import (  # noqa: E402, F401
    _dashboard_html_response,
    _DashboardFile,
    _validated_dashboard_file,
    mount_dashboard,
)
from agent_bom.api.server_schedules import _enqueue_scheduled_scan  # noqa: E402, F401
from agent_bom.api.server_storage import (  # noqa: E402, F401
    _analytics_backend_config,
    _analytics_health,
    _apply_worker_thread_limit,
    _backend_name,
    _control_plane_backend,
    _log_control_plane_auth_posture,
    _postgres_portability_health,
    _preflight_postgres_tenant_isolation,
    _storage_health,
    _validate_configured_registries,
    initialize_storage,
)


async def _prewarm_demo_story() -> None:
    try:
        from agent_bom.api.routes.demo_estate import prewarm_demo_story

        await asyncio.to_thread(prewarm_demo_story)
    except Exception:  # noqa: BLE001
        _logger.warning("demo story prewarm skipped", exc_info=False)


def _log_rate_limit_key_status() -> None:
    try:
        from agent_bom.api.middleware import get_rate_limit_key_status

        _rl_status = get_rate_limit_key_status()
        if _rl_status["status"] == "max_age_exceeded":
            _logger.error(
                "rate_limit_key_rotation status=%s age_days=%s message=%s",
                _rl_status["status"],
                _rl_status["age_days"],
                _rl_status["message"],
            )
        elif _rl_status["status"] in {"rotation_due", "ephemeral", "unknown_age"}:
            _logger.warning(
                "rate_limit_key_rotation status=%s age_days=%s message=%s",
                _rl_status["status"],
                _rl_status["age_days"],
                _rl_status["message"],
            )
        else:
            _logger.info("rate_limit_key_rotation status=%s age_days=%s", _rl_status["status"], _rl_status["age_days"])
    except Exception:
        _logger.debug("rate_limit_key_rotation status check skipped", exc_info=False)


@asynccontextmanager
async def _lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
    """Start background cleanup task on startup, cancel on shutdown."""
    preflight_storage_backends()
    _state_home.activate_demo_state_dir()
    _log_control_plane_auth_posture()
    _host_guard.log_host_policy()
    warn_if_ephemeral_hmac_key()
    _apply_worker_thread_limit()
    configure_otel_tracing()
    _preflight_postgres_tenant_isolation()
    _validate_configured_registries()
    initialize_storage()
    start_route_warmup(app_instance)
    _log_rate_limit_key_status()

    global _cleanup_task
    from agent_bom.api.scan_job_reconciliation import fail_orphaned_active_scan_jobs, reconcile_scan_jobs_active

    try:
        store = _get_store()
        fail_orphaned_active_scan_jobs(store)
        reconcile_scan_jobs_active(store)
    except Exception:  # noqa: BLE001
        _logger.debug("scan job metric startup reconciliation skipped", exc_info=False)

    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scheduler background loop
    global _scheduler_task
    from agent_bom.api.scheduler import scheduler_loop

    _scheduler_task = asyncio.create_task(scheduler_loop(_get_schedule_store(), _enqueue_scheduled_scan))

    # ── Cloud-connection scan scheduler (Phase B.2) ──
    # Opt-in background loop that re-scans due cloud connections so a connection
    # with an interval keeps evaluating without a manual /scan call. Off unless
    # AGENT_BOM_CONNECTIONS_SCHEDULER is set, so it never runs in CLI/dev.
    global _connection_scheduler_task
    from agent_bom.api.connection_scheduler import connection_scheduler_loop, connections_scheduler_enabled

    if connections_scheduler_enabled():
        _connection_scheduler_task = asyncio.create_task(connection_scheduler_loop())
        _logger.info("Cloud-connection scan scheduler enabled")

    # ── Scheduled findings-export scheduler (#4040) ──
    # Opt-in background loop that streams a tenant's findings to a connect-once
    # destination (object store / warehouse) on a cron cadence. Off unless
    # AGENT_BOM_EXPORT_SCHEDULER is set, so it never runs in CLI/dev.
    global _export_scheduler_task
    from agent_bom.api.export_scheduler import export_scheduler_enabled, export_scheduler_loop

    if export_scheduler_enabled():
        _export_scheduler_task = asyncio.create_task(export_scheduler_loop())
        _logger.info("Findings-export scheduler enabled")

    # ── Cross-cloud side-scan scheduler (#4158 Stage 4) ──
    # Opt-in background loop that re-runs the shipped Azure/GCP side-scan executor
    # for each configured target on a cadence, so a CWPP side-scan keeps
    # evaluating without a manual CLI/API call. Off unless
    # AGENT_BOM_SIDESCAN_SCHEDULER is set (and the executor's own
    # AGENT_BOM_SIDESCAN gate), so it never runs in CLI/dev — a scheduled
    # snapshot side-scan is never a surprise cloud write.
    global _side_scan_scheduler_task
    from agent_bom.api.side_scan_scheduler import side_scan_scheduler_loop, sidescan_scheduler_enabled

    if sidescan_scheduler_enabled():
        _side_scan_scheduler_task = asyncio.create_task(side_scan_scheduler_loop())
        _logger.info("Cross-cloud side-scan scheduler enabled")

    global _advisory_rematch_task
    from agent_bom.api.advisory_rematch import start_advisory_rematch_task

    _advisory_rematch_task = start_advisory_rematch_task()

    # ── Exact-batch graph correlation scheduler ──
    # Enabled by default for supported durable stores and strict-freshness only.
    # It correlates the child snapshots from one explicit multi-target scan
    # batch; it never groups tenant-latest rows, recurring source ids, mutable
    # tags, or similar labels. Unsupported stores no-op with a bounded metric.
    global _auto_correlation_task
    from agent_bom.api.auto_correlation import (
        auto_correlation_enabled,
        auto_correlation_job_store_skip_reason,
        auto_correlation_loop,
    )

    if auto_correlation_enabled():
        auto_correlation_job_store = _get_store()
        auto_correlation_skip_reason = auto_correlation_job_store_skip_reason(auto_correlation_job_store)
        if auto_correlation_skip_reason:
            from agent_bom.api.metrics import record_auto_correlation

            record_auto_correlation(outcome="skipped", reason=auto_correlation_skip_reason)
            _logger.info("Exact-batch graph correlation skipped: %s", auto_correlation_skip_reason.replace("_", " "))
        else:
            _auto_correlation_task = asyncio.create_task(auto_correlation_loop(auto_correlation_job_store, _stores._get_graph_store()))
            _logger.info("Exact-batch graph correlation configured; durable-store eligibility check scheduled")

    # ── Distributed scan dispatch ──
    # Start a per-replica claim-loop so queued scans are stolen across the
    # cluster. No-op on single-node / non-Postgres deployments.
    _scan_worker = None
    try:
        from agent_bom.api.scan_queue import (
            DistributedScanWorker,
            distributed_scans_enabled,
            store_supports_dispatch,
        )

        _scan_store = _get_store()
        if distributed_scans_enabled() and store_supports_dispatch(_scan_store):
            _scan_worker = DistributedScanWorker(_scan_store)
            await _scan_worker.start()
    except Exception:  # noqa: BLE001
        _logger.error("Distributed scan worker failed to start; continuing single-node")
        _scan_worker = None

    demo_seed_task: asyncio.Task[None] | None = None
    if os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in {"1", "true", "yes", "on"}:
        from agent_bom.config import demo_story_prewarm_enabled

        demo_seed_task = _demo_boot_seed.start_demo_estate_boot_seed(_prewarm_demo_story if demo_story_prewarm_enabled() else None)

    from agent_bom.api.report_queue import start_report_worker

    _report_worker = await start_report_worker()
    yield

    # ── Graceful shutdown ──
    # Flip readiness to not-ready so upstream load balancers stop routing new
    # traffic while in-flight requests drain. The readiness probe reads
    # _shutting_down under the same module; see meta_routes.
    global _shutting_down
    _shutting_down = True
    await _report_worker.stop(float(os.environ.get("AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "25")))
    await _demo_boot_seed.drain_demo_estate_boot_seed(demo_seed_task, float(os.environ.get("AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "25")))
    # Stop claiming new distributed work before draining in-flight scans.
    if _scan_worker is not None:
        try:
            await _scan_worker.stop()
        except Exception:  # noqa: BLE001
            _logger.debug("scan worker stop skipped", exc_info=False)
    for task in (_scheduler_task, _connection_scheduler_task, _export_scheduler_task, _side_scan_scheduler_task):
        if task:
            task.cancel()
    for task in (_advisory_rematch_task, _auto_correlation_task, _cleanup_task):
        if task:
            task.cancel()
    # Drain in-flight scans. Honor the operator-configured drain budget so the
    # pod exits before Kubernetes force-kills at terminationGracePeriodSeconds.
    # Default 25s leaves a 5s margin under the recommended 30s Helm value.
    _drain_seconds = float(os.environ.get("AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "25"))
    try:
        await asyncio.wait_for(
            asyncio.to_thread(lambda: shutdown_scan_executor(wait=True, cancel_futures=False)),
            timeout=_drain_seconds,
        )
    except asyncio.TimeoutError:
        _logger.warning(
            "shutdown drain timeout after %.1fs; force-cancelling in-flight scans",
            _drain_seconds,
        )
        shutdown_scan_executor(wait=False, cancel_futures=True)
    # Close Postgres connection pool if active
    try:
        if postgres_deployment_configured():
            from agent_bom.api import postgres_common as _postgres_common

            _postgres_common.reset_pool()
    except Exception:
        _logger.debug("Postgres pool close skipped")
    try:
        if (active_analytics := peek_analytics_store()) is not None and hasattr(active_analytics, "close"):
            active_analytics.close()
    except Exception:
        _logger.debug("Analytics store close skipped", exc_info=False)


app = FastAPI(
    title=f"{PRODUCT_NAME} API",
    description=f"{POSITIONING_META}. {TAGLINE_CHAIN}.",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None if APIKeyMiddleware._DOCS_DISABLED else "/openapi.json",
    lifespan=_lifespan,
)
configure_docs(app, disabled=APIKeyMiddleware._DOCS_DISABLED)

_default_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
_cors_env = resolved_cors_origins_raw()
_cors_origins: list[str] = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else _default_origins
_api_key: str | None = None
DEFAULT_RATE_LIMIT_RPM = DEFAULT_SCAN_RATE_LIMIT_RPM
_rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM
_env_api_keys_seeded = False
_runtime_api_key_seeded = False


def _parse_cors_origins_from_env(default: list[str]) -> tuple[list[str], bool]:
    raw = resolved_cors_origins_raw()
    if not raw:
        return default, False
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or default, "*" in origins


def _seed_api_key_store_from_env() -> bool:
    """Seed RBAC keys from AGENT_BOM_API_KEYS (env or ``*_FILE``) for direct ASGI imports."""
    global _env_api_keys_seeded

    from agent_bom.api.secret_source import resolve_secret

    configured = resolve_secret("AGENT_BOM_API_KEYS")
    if not configured:
        return False
    if _env_api_keys_seeded:
        return get_key_store().has_keys()

    seed_operator_keys("env", parse_env_api_keys(configured))
    _env_api_keys_seeded = True
    return get_key_store().has_keys()


def _seed_runtime_api_key(raw_key: str | None) -> bool:
    """Seed the process-local key store from ``configure_api(api_key=...)``."""
    global _runtime_api_key_seeded

    value = (raw_key or "").strip()
    if not value:
        return False
    if _runtime_api_key_seeded:
        return get_key_store().has_keys()

    role = get_dev_api_role() if value == get_dev_api_key() else Role.ADMIN
    seed_operator_keys("runtime", [(value, f"runtime:{role.value}", role)])
    _runtime_api_key_seeded = True
    return True


def _apply_cors_middleware(origins: list[str]) -> None:
    """Install or refresh the CORS middleware with the current origin policy."""
    _replace_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials="*" not in origins,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Agent-Bom-CSRF", "X-Agent-Bom-Session-Resume"],
    )
    if app.middleware_stack is not None:
        app.middleware_stack = app.build_middleware_stack()


def _replace_middleware(middleware_cls: object, /, **kwargs: object) -> None:
    """Replace a middleware class in-place so runtime config updates actually apply."""
    app.user_middleware = [m for m in app.user_middleware if m.cls is not middleware_cls]
    app.user_middleware.insert(0, Middleware(cast(Any, middleware_cls), **kwargs))


def _validated_rate_limit_rpm(value: int) -> int:
    try:
        rpm = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("rate_limit_rpm must be an integer") from exc
    if rpm < 1:
        raise ValueError("rate_limit_rpm must be at least 1")
    if rpm > MAX_RATE_LIMIT_RPM:
        raise ValueError(f"rate_limit_rpm must be <= {MAX_RATE_LIMIT_RPM}")
    return rpm


def _is_loopback_listener(host: str) -> bool:
    cleaned = host.strip().lower()
    if cleaned == "localhost":
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


# CORS: defaults to localhost; configure via configure_api() before startup
_apply_cors_middleware(_cors_origins)


# ─── Trust headers middleware ──────────────────────────────────────────────────


app.add_middleware(TrustHeadersMiddleware)
app.add_middleware(ForegroundActivityMiddleware)
# Starlette defaults to compresslevel=9. Measured on the 2.7 MB
# /v1/graph?limit=5000 payload: level 9 cost 32.5ms for 175.4 KB, level 6 cost
# 17.7ms for 185.2 KB; 6 is the level nginx and friends ship. Since Starlette
# 1.4 (the pinned floor), bodies of thread_minimum_size or more are compressed
# in a worker thread, so a large scan result does not stall the event loop.
app.add_middleware(GZipMiddleware, minimum_size=500, compresslevel=6, thread_minimum_size=128 * 1024)

# wrap FastAPI's bare ``{"detail": ...}`` errors in the
# structured ``{error: {code, message, correlation_id, details}}`` envelope.
install_error_envelope(app)


def configure_api(
    cors_origins: list[str] | None = None,
    cors_allow_all: bool = False,
    api_key: str | None = None,
    rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM,
    allow_unauthenticated: bool | None = None,
    listener_host: str | None = None,
) -> None:
    """Configure API hardening before server startup.

    Call this before uvicorn.run() to set CORS, auth, and rate limiting.
    """
    global _cors_origins, _api_key, _rate_limit_rpm

    validated_rate_limit_rpm = _validated_rate_limit_rpm(rate_limit_rpm)

    effective_origins = ["*"] if cors_allow_all else list(cors_origins or _cors_origins)
    if "*" in effective_origins and (not listener_host or not _is_loopback_listener(listener_host)):
        raise ValueError("Wildcard CORS requires an explicit loopback listener_host")
    _cors_origins = effective_origins
    _apply_cors_middleware(_cors_origins)

    _api_key = api_key
    _rate_limit_rpm = validated_rate_limit_rpm

    from agent_bom.api.secret_source import secret_is_configured

    env_key_store_configured = _seed_api_key_store_from_env()
    runtime_key_store_configured = _seed_runtime_api_key(api_key)
    static_api_key_configured = secret_is_configured("AGENT_BOM_API_KEY")

    api_key_configured = bool(api_key or static_api_key_configured or env_key_store_configured or runtime_key_store_configured)
    # Honor AGENT_BOM_ALLOW_UNAUTHENTICATED_API on every (re)configure, not just
    # when the caller omits the argument. CLI wrappers (`serve` / `api`) pass the
    # ``--allow-insecure-no-auth`` flag as an explicit bool, so a ``None`` check
    # alone would silently drop the env-var opt-out and leave the loopback banner
    # claiming unauthenticated access while the API actually fails closed (401).
    # Non-loopback binds stay fail-closed because the CLI auth gate refuses them
    # before configure_api runs unless real auth or the explicit flag is present.
    allow_unauthenticated = bool(allow_unauthenticated) or _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API")
    # Single derivation: the env-based credential-source facts are computed once
    # here (and identically by the CLI serve gate) instead of re-derived per
    # surface. The runtime status, /health, and the startup log all read this.
    from agent_bom.api.auth_posture import apply_auth_posture, derive_auth_posture

    posture = derive_auth_posture(
        api_key_configured=api_key_configured,
        allow_unauthenticated=allow_unauthenticated,
        listener_host=listener_host,
    )
    apply_auth_posture(posture)
    # The control-plane auth-posture warning is emitted once at serving start
    # (see ``_log_control_plane_auth_posture`` in ``_lifespan``) rather than
    # here: ``configure_api`` runs at import via ``configure_api_from_env`` with
    # only environment auth visible, so logging here would emit a misleading
    # transient "no auth configured" CRITICAL before a CLI ``--api-key`` flag
    # reconfigures. Logging at lifespan reflects the final effective posture.

    # _replace_middleware inserts at the front. Response headers wrap admission:
    # coarse IP limit, auth, body-size, then tenant-scoped rate limiting. Bodies
    # are buffered only after auth; authenticated reads retain twice the budget.
    _replace_middleware(
        RateLimitMiddleware,
        scan_rpm=_rate_limit_rpm,
        read_rpm=_rate_limit_rpm * 5,
        authenticated_read_rpm=_rate_limit_rpm * 10,
    )
    # Authentication can be optional; authorization cannot. The principal
    # resolver stays installed in no-auth mode so credential-less callers get
    # NO_AUTH_ROLE and the same route role matrix (DEMO_ESTATE clamps to viewer).

    if _config.API_RESULT_PUSH_MAX_BYTES <= 0:
        raise ValueError("AGENT_BOM_API_RESULT_PUSH_MAX_BYTES must be positive")
    _replace_middleware(MaxBodySizeMiddleware, path_limits={"/v1/results/push": _config.API_RESULT_PUSH_MAX_BYTES})
    _replace_middleware(APIKeyMiddleware, api_key=api_key, allow_unauthenticated=allow_unauthenticated)
    _replace_middleware(GlobalRateLimitMiddleware, rpm=global_ip_rate_limit_rpm())
    _host_guard.configure_host_policy(posture.listener_host, _cors_origins)
    _replace_middleware(_host_guard.HostAllowlistMiddleware)  # Host check precedes limits, auth, routes, cookies.
    # Wrap admission denials with security/correlation headers without reading bodies.
    _replace_middleware(TrustHeadersMiddleware)
    if app.middleware_stack is not None:
        app.middleware_stack = app.build_middleware_stack()


def configure_api_from_env() -> None:
    """Configure API hardening for direct ASGI imports such as raw uvicorn."""
    from agent_bom.api.secret_source import resolve_secret

    api_key = resolve_secret("AGENT_BOM_API_KEY") or None
    origins, allow_all = _parse_cors_origins_from_env(_default_origins)
    configure_api(
        cors_origins=origins,
        cors_allow_all=allow_all,
        api_key=api_key,
        rate_limit_rpm=DEFAULT_RATE_LIMIT_RPM,
        listener_host=os.environ.get("AGENT_BOM_API_HOST"),
    )


configure_api_from_env()


# ─── Scan Pipeline (extracted to api/pipeline.py) ────────────────────────────
from agent_bom.api.pipeline import (  # noqa: E402
    PIPELINE_DAG_EDGES,  # noqa: F401 — re-exported for tests/artifact consumers
    PIPELINE_DAG_EVENT_SCHEMA,  # noqa: F401 — re-exported for tests/artifact consumers
    PIPELINE_STEPS,  # noqa: F401 — re-exported for tests
    ScanPipeline,  # noqa: F401 — re-exported for tests
    _executor,  # noqa: F401 — re-exported for tests (may be replaced on shutdown; use get_executor() for new submissions)
    _run_scan_sync,  # noqa: F401 — re-exported for backward compat
    _sync_scan_agents_to_fleet,  # noqa: F401 — re-exported for tests
    get_executor,  # noqa: F401 — re-exported for tests
    iter_pipeline_dag_event_records,  # noqa: F401 — re-exported for tests/artifact consumers
    pipeline_dag_events_jsonl,  # noqa: F401 — re-exported for tests/artifact consumers
    shutdown_scan_executor,
)

# ─── Route modules ────────────────────────────────────────────────────────
from agent_bom.api.server_routes import register_domain_routes  # noqa: E402

register_domain_routes(app)

# Resolve agent-bom-issued (abi_) identity tokens through the lifecycle store so
# the proxy/gateway honor issuance, rotation overlap, and revocation.
from agent_bom.api.agent_identity_store import register_local_identity_verifier  # noqa: E402

register_local_identity_verifier()

# Re-export proxy, connectors and scan helpers for backward compatibility
from agent_bom.api.ai_scan_runtime import _dataclass_to_dict  # noqa: E402, F401
from agent_bom.api.routes.connectors import _load_registry  # noqa: E402, F401
from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics  # noqa: E402, F401
from agent_bom.api.scan_path_jail import _sanitize_api_path  # noqa: E402, F401

_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None
_connection_scheduler_task: asyncio.Task | None = None
_export_scheduler_task: asyncio.Task | None = None
_side_scan_scheduler_task: asyncio.Task | None = None
_advisory_rematch_task: asyncio.Task | None = None
_auto_correlation_task: asyncio.Task | None = None
# Flipped to True during graceful shutdown so the /readyz probe goes red
# and upstream load balancers stop sending new traffic while in-flight
# requests complete under the drain budget.
_shutting_down: bool = False


_STUCK_JOB_TIMEOUT = 1800  # 30 minutes — mark RUNNING jobs as FAILED


async def _cleanup_loop() -> None:
    """Background task that removes expired jobs and unsticks RUNNING jobs.

    Also drives the tier-B (replay-only) evidence TTL purge from issue
    #2261: rows in ``proxy_replay_log`` with ``not_after < now`` are deleted
    on every tick.
    """
    from agent_bom.api.campaign_reconciliation import poll_campaign_reconciliation

    while True:
        await asyncio.to_thread(poll_campaign_reconciliation)
        await asyncio.sleep(60)
        await _cleanup_tick()


async def _cleanup_tick() -> None:
    """One maintenance pass: TTL purges, partition retention, job reconcile.

    EVERY work item is synchronous store/DB work and is offloaded to a worker
    thread. Left inline it ran on the event loop once a minute; on Postgres at
    volume the partition DDL alone freezes the whole control plane for the
    duration of the tick. Each hook stays fail-open so a backend hiccup skips
    one item instead of killing the loop.
    """
    store = _get_store()
    await asyncio.to_thread(expire_jobs_and_snapshots, store, _JOB_TTL_SECONDS)
    # Public demo self-heal: if AGENT_BOM_DEMO_ESTATE is on and the curated
    # scan job is missing/empty (TTL wipe, partial boot, operator reset),
    # reseed without waiting for a container restart. Cheap no-op when a
    # usable demo job is already present.
    try:
        from agent_bom.demo_estate.bootstrap import (
            demo_estate_enabled,
            maybe_bootstrap_demo_estate,
        )

        if demo_estate_enabled():
            await asyncio.to_thread(maybe_bootstrap_demo_estate)
    except Exception:  # noqa: BLE001
        _logger.warning("demo estate cleanup-loop reseed skipped", exc_info=False)
    # Tier-B replay-log TTL purge (#2261); wrapped so a backend hiccup never takes down the cleanup loop.
    try:
        from agent_bom.api.proxy_replay_store import get_proxy_replay_store

        removed = await asyncio.to_thread(lambda: get_proxy_replay_store().cleanup_expired())
        if removed:
            _logger.info("proxy_replay_log cleanup removed %d expired rows", removed)
    except Exception:  # noqa: BLE001
        _logger.debug("proxy_replay_log cleanup skipped", exc_info=False)
    # Hub observations partition retention (#3463). Postgres-only; no-op on
    # SQLite and legacy unpartitioned tables. Fail-open like other cleanup
    # hooks so a backend hiccup never stops the loop.
    try:
        from agent_bom.api.hub_observations_partition import run_hub_observations_retention

        dropped_partitions = await asyncio.to_thread(run_hub_observations_retention)
        if dropped_partitions:
            _logger.info(
                "hub_findings_current_observations retention dropped %d partition(s)",
                dropped_partitions,
            )
    except Exception:  # noqa: BLE001
        _logger.debug("hub observations retention skipped", exc_info=False)
    # Generic partition maintenance for the other append-only tables (#3463):
    # ensure next partitions exist and roll over expired ones. Postgres-only;
    # a strict no-op on SQLite and on any table an operator has not converted
    # to declarative partitioning. Fail-open like the hooks above.
    try:
        from agent_bom.api.partition_maintenance import run_partition_retention

        partition_results = await asyncio.to_thread(run_partition_retention)
        for table, (partitions_created, partitions_dropped) in partition_results.items():
            _logger.info(
                "%s partition maintenance: %d created, %d dropped",
                table,
                partitions_created,
                partitions_dropped,
            )
    except Exception:  # noqa: BLE001
        _logger.debug("partition maintenance skipped", exc_info=False)
    # NHI lifecycle enforcement (#nhi): expire lingering JIT grants, opt-in
    # dormant-identity deprovision, advisory token rotation-due flagging.
    # Backend-agnostic and fail-open — a store error logs and is skipped so
    # the loop survives. Timestamp injected for deterministic, replica-safe
    # transitions.
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store, run_nhi_lifecycle_cleanup
        from agent_bom.api.governance_audit_log import get_governance_audit_log

        nhi_now = datetime.now(timezone.utc)
        nhi_result = await asyncio.to_thread(
            lambda: run_nhi_lifecycle_cleanup(
                get_agent_identity_store(),
                now=nhi_now,
                audit_log=get_governance_audit_log(),
            )
        )
        grants = nhi_result.get("grants", {})
        dormant = nhi_result.get("dormant", {})
        rotation = nhi_result.get("rotation", {})
        acted = grants.get("expired", 0) + grants.get("pruned", 0) + dormant.get("revoked", 0) + rotation.get("flagged", 0)
        if acted:
            _logger.info(
                "nhi lifecycle cleanup: %d grants expired, %d denied pruned, %d dormant revoked, %d rotation-due",
                grants.get("expired", 0),
                grants.get("pruned", 0),
                dormant.get("revoked", 0),
                rotation.get("flagged", 0),
            )
    except Exception:  # noqa: BLE001 — cleanup must never crash the loop
        _logger.warning(
            "nhi lifecycle cleanup skipped this tick; check the agent-identity store and governance audit-log backend connectivity",
            exc_info=False,
        )
    # Managed-trial lifecycle: access is revoked at expiry, while data is
    # deleted only after the configured grace period. This hook is opt-in
    # and never runs in ordinary self-hosted deployments.
    try:
        from agent_bom.api.managed_trial import managed_trial_enabled

        if managed_trial_enabled():
            from agent_bom.api.tenant_lifecycle import run_managed_trial_lifecycle_tick

            lifecycle_result = await asyncio.to_thread(run_managed_trial_lifecycle_tick)
            if lifecycle_result["expired"] or lifecycle_result["deleted"]:
                _logger.info(
                    "managed-trial lifecycle: %d expired, %d deleted",
                    lifecycle_result["expired"],
                    lifecycle_result["deleted"],
                )
    except Exception:  # noqa: BLE001 — lifecycle cleanup remains retryable
        _logger.warning(
            "managed-trial lifecycle cleanup skipped this tick; check the lifecycle and tenant stores",
            exc_info=False,
        )
    # Unstick jobs that have been RUNNING for too long
    try:
        from agent_bom.api.scan_job_reconciliation import fail_stale_active_scan_jobs, reconcile_scan_jobs_active

        now = datetime.now(timezone.utc)
        await asyncio.to_thread(_fail_stuck_running_jobs, store, now)
        await asyncio.to_thread(fail_stale_active_scan_jobs, store, timeout_seconds=_STUCK_JOB_TIMEOUT, now=now)
        await asyncio.to_thread(reconcile_scan_jobs_active, store)
    except Exception:  # noqa: BLE001
        pass


def _fail_stuck_running_jobs(store: Any, now: _datetime.datetime) -> None:
    """Mark in-process jobs stuck in RUNNING past the timeout as FAILED.

    Synchronous by design — ``store.put`` is a DB write, so the caller runs
    this in a worker thread.
    """
    stuck_jobs: list[Any] = []
    with _jobs_lock:
        for job in list(_jobs.values()):
            if job.status == JobStatus.RUNNING and job.created_at:
                try:
                    job_created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    continue
                if (now - job_created).total_seconds() > _STUCK_JOB_TIMEOUT:
                    job.status = JobStatus.FAILED
                    job.error = "Timed out (stuck in RUNNING state)"
                    job.completed_at = now.isoformat()
                    stuck_jobs.append(job)

    # Durable stores may block on database I/O. Persist after releasing the
    # process-wide cache lock so unrelated job reads and writes keep flowing.
    for job in stuck_jobs:
        store.put(job)


# ─── Meta Routes ─────────────────────────────────────────────────────────────


def _dashboard_dist_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "ui_dist"


def _ui_disabled() -> bool:
    """True when the bundled dashboard is disabled (`serve --no-ui` / legacy `api`).

    Mirrors the ``AGENT_BOM_NO_UI`` gate that keeps ``_mount_dashboard`` from
    mounting the SPA. The ``/`` route is registered independently of that mount,
    so it must honour the same gate or ``--no-ui`` would still serve the
    dashboard index at the root.
    """
    return bool(os.environ.get("AGENT_BOM_NO_UI"))


def _dashboard_index_file() -> _DashboardFile | None:
    """Return the packaged dashboard index path when bundled UI assets exist."""

    return _validated_dashboard_file(_dashboard_dist_dir(), "index.html")


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root(request: Request) -> Response:
    if not _ui_disabled():
        dashboard_index = _dashboard_index_file()
        if dashboard_index:
            response = _dashboard_html_response(dashboard_index)
            _maybe_attach_dev_session_cookie(response, request)
            return response
    return RedirectResponse(url="/docs")


def _public_health() -> PublicHealthResponse:
    from agent_bom.api.auth_posture import get_auth_runtime_status

    auth_runtime = get_auth_runtime_status()
    return PublicHealthResponse(
        status="ok",
        version=__version__,
        auth_required=bool(auth_runtime["auth_required"]),
        auth_configured=bool(auth_runtime.get("auth_configured", False)),
        configured_auth_modes=list(cast(list[str], auth_runtime["configured_modes"])),
        unauthenticated_allowed=bool(auth_runtime.get("unauthenticated_allowed", False)),
    )


@app.get("/brand/mark.svg", include_in_schema=False, tags=["meta"])
async def brand_mark_svg() -> Any:
    """Serve the canonical BOM agent-HUD mark for OpenAPI /docs favicon chrome."""
    from fastapi.responses import FileResponse, Response

    from agent_bom.output.brand_tokens import MARK_SVG_DARK

    root = Path(__file__).resolve().parents[3]
    for candidate in (
        root / "docs" / "images" / "brand" / "mark-dark.svg",
        root / "ui" / "public" / "brand" / "mark-dark.svg",
    ):
        if candidate.is_file():
            return FileResponse(candidate, media_type="image/svg+xml")
    return Response(content=MARK_SVG_DARK, media_type="image/svg+xml")


@app.get("/health", response_model=PublicHealthResponse, tags=["meta"])
async def health() -> PublicHealthResponse:
    """Liveness probe."""
    return _public_health()


@app.get("/v1/system/health", response_model=SystemHealthResponse, tags=["meta"], responses=ERROR_RESPONSES)
async def system_health() -> SystemHealthResponse:
    """Authenticated operator diagnostics for configured subsystems."""
    from agent_bom.api.auth_posture import get_auth_runtime_status
    from agent_bom.api.connection_scheduler import connections_scheduler_enabled
    from agent_bom.entitlements import load_entitlement_state

    auth_runtime = get_auth_runtime_status()
    return SystemHealthResponse(
        status="ok",
        version=__version__,
        auth_required=bool(auth_runtime["auth_required"]),
        auth_configured=bool(auth_runtime.get("auth_configured", False)),
        configured_auth_modes=list(cast(list[str], auth_runtime["configured_modes"])),
        unauthenticated_allowed=bool(auth_runtime.get("unauthenticated_allowed", False)),
        connections_scheduler_enabled=connections_scheduler_enabled(),
        tracing=TracingHealth(**get_tracing_health()),
        analytics=_analytics_health(),
        storage=_storage_health(),
        entitlements=EntitlementHealth(**load_entitlement_state().health_summary()),
        experimental_features=[ExperimentalFeatureHealth.model_validate(item) for item in feature_status()],
    )


@app.get("/healthz", response_model=PublicHealthResponse, tags=["meta"])
async def healthz() -> PublicHealthResponse:
    """Kubernetes-style liveness probe alias for /health."""
    return await health()


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


@app.get("/readyz", tags=["meta"])
async def readiness() -> JSONResponse:
    """Readiness probe — returns 503 during drain or when dependencies are unhealthy.

    Kubernetes removes the pod from the service endpoint list on first 503,
    so new requests stop arriving while in-flight work drains under the
    operator-configured drain budget (AGENT_BOM_SHUTDOWN_DRAIN_SECONDS).
    """
    from agent_bom.api.readiness import control_plane_readiness_response

    return await control_plane_readiness_response(lambda: _shutting_down)


@app.get("/livez", response_model=PublicHealthResponse, tags=["meta"])
async def liveness() -> PublicHealthResponse:
    """Kubernetes-style liveness probe alias for /health."""
    return await health()


@app.get("/ping", tags=["meta"])
async def ping() -> dict[str, str]:
    """Minimal ping endpoint for load balancers and smoke checks."""
    return {"status": "ok"}


@app.get("/status", response_model=HealthResponse, tags=["meta"])
async def status() -> HealthResponse:
    """Operator status alias for the health payload."""
    return await system_health()


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


def _mount_dashboard(application: FastAPI) -> None:
    mount_dashboard(application, _dashboard_dist_dir())


_mount_dashboard(app)
