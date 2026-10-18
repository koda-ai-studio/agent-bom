"""Storage initialization and operator health for the API server."""

from __future__ import annotations

import logging

from agent_bom import config as _config
from agent_bom.api import stores as _stores
from agent_bom.api.audit_log import get_audit_log
from agent_bom.api.auth import get_key_store
from agent_bom.api.models import AnalyticsHealth, PostgresPortabilityHealth, StorageHealth
from agent_bom.api.storage.analytics import peek_analytics_store
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.stores import (
    _get_credential_ref_store,
    _get_schedule_store,
    _get_source_store,
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
from agent_bom.core.settings import env_raw

_logger = logging.getLogger("agent_bom.api.server")


def _analytics_backend_config() -> tuple[str, str | None]:
    """Resolve the requested analytics backend and configured ClickHouse URL."""
    backend = env_raw("AGENT_BOM_ANALYTICS_BACKEND", "").strip().lower()
    clickhouse_url = env_raw("AGENT_BOM_CLICKHOUSE_URL", "").strip() or None
    if backend in {"", "auto"}:
        backend = "clickhouse" if clickhouse_url else "disabled"
    return backend, clickhouse_url


def _analytics_health() -> AnalyticsHealth:
    """Return the active analytics backend contract for operators."""
    backend, clickhouse_url = _analytics_backend_config()
    active_store = peek_analytics_store()
    if active_store is None:
        return AnalyticsHealth(
            backend=backend if backend != "disabled" else "disabled",
            enabled=False,
            buffered=False,
            clickhouse_url_configured=bool(clickhouse_url),
        )

    store_name = type(active_store).__name__
    buffered = hasattr(active_store, "flush_interval") and hasattr(active_store, "max_batch")
    return AnalyticsHealth(
        backend="clickhouse" if "ClickHouse" in store_name or buffered else backend,
        enabled=store_name != "NullAnalyticsStore",
        buffered=buffered,
        clickhouse_url_configured=bool(clickhouse_url),
        flush_interval_seconds=float(getattr(active_store, "flush_interval", 0.0)) if buffered else None,
        max_batch=int(getattr(active_store, "max_batch", 0)) if buffered else None,
        queue_capacity=int(getattr(active_store, "queue_capacity", 0)) if buffered else None,
        queue_depth=int(getattr(active_store, "queue_depth", 0)) if buffered else None,
        dropped_count=int(getattr(active_store, "dropped_count", 0)) if buffered else None,
    )


def _backend_name(store: object | None) -> str:
    if store is None:
        return "disabled"
    name = type(store).__name__.lower()
    if "snowflake" in name:
        return "snowflake"
    if "postgres" in name:
        return "postgres"
    if "sqlite" in name:
        return "sqlite"
    if "clickhouse" in name:
        return "clickhouse"
    if "memory" in name:
        return "inmemory"
    if "null" in name:
        return "disabled"
    return type(store).__name__


def _control_plane_backend(storage: StorageHealth) -> str:
    primary = [storage.job_store, storage.fleet_store, storage.policy_store, storage.source_store]
    if any(name == "snowflake" for name in primary):
        return "snowflake"
    if any(name == "postgres" for name in primary):
        return "postgres"
    if any(name == "sqlite" for name in primary):
        return "sqlite"
    return "inmemory"


def _postgres_portability_health(control_plane_backend: str) -> PostgresPortabilityHealth | None:
    """Return declarative Postgres posture without blocking the health route."""
    if control_plane_backend != "postgres":
        return None
    from agent_bom.storage.postgres_capabilities import declared_postgres_portability

    posture = declared_postgres_portability()
    return PostgresPortabilityHealth(
        provider=posture.provider,
        declared_hint=posture.declared_hint,
        contract=posture.contract,
        evidence=posture.evidence,
        next_action=posture.next_action,
    )


def _storage_health() -> StorageHealth:
    try:
        source_store = _get_source_store()
    except RuntimeError:
        source_store = None
    try:
        credential_ref_store = _get_credential_ref_store()
    except RuntimeError:
        credential_ref_store = None
    try:
        schedule_store = _get_schedule_store()
    except RuntimeError:
        schedule_store = None

    storage = StorageHealth(
        job_store=_backend_name(_stores._store or _stores._get_store()),
        fleet_store=_backend_name(_stores._fleet_store or _stores._get_fleet_store()),
        policy_store=_backend_name(_stores._policy_store or _stores._get_policy_store()),
        source_store=_backend_name(_stores._source_store or source_store),
        credential_ref_store=_backend_name(_stores._credential_ref_store or credential_ref_store),
        schedule_store=_backend_name(_stores._schedule_store or schedule_store),
        exception_store=_backend_name(_stores._exception_store or _stores._get_exception_store()),
        trend_store=_backend_name(_stores._trend_store or _stores._get_trend_store()),
        graph_store=_backend_name(_stores._graph_store or _stores._get_graph_store()),
        key_store=_backend_name(get_key_store()),
        audit_log=_backend_name(get_audit_log()),
    )
    storage.control_plane_backend = _control_plane_backend(storage)
    storage.postgres = _postgres_portability_health(storage.control_plane_backend)
    return storage


def _log_control_plane_auth_posture() -> None:
    """Emit the control-plane auth-posture warning once, at serving start.

    Reads the *final* runtime auth status so the log reflects the effective
    posture after every ``configure_api`` call. The module-level
    ``configure_api_from_env`` runs at import with only environment auth in
    scope, so emitting from ``configure_api`` itself surfaced a misleading
    transient "no auth configured" CRITICAL whenever the key arrived via a CLI
    ``--api-key`` flag (which is not in the environment yet). Logging here — the
    lifespan startup, after the CLI has reconfigured — avoids that.
    """
    from agent_bom.api.auth_posture import get_auth_posture

    posture = get_auth_posture()
    # One structured line summarizing the single derived posture (effective
    # sources in precedence order, anonymous state, listener scope, trusted-proxy
    # and OIDC status). This is the same object /health and the middleware read.
    _logger.info(posture.summary_line())

    auth_configured = posture.auth_configured
    unauthenticated_allowed = posture.anonymous_allowed
    if not auth_configured and not unauthenticated_allowed:
        _logger.critical(
            "SECURITY: No control-plane authentication configured; protected API endpoints will fail closed. "
            "Set AGENT_BOM_API_KEY, AGENT_BOM_API_KEYS, OIDC/SAML/proxy auth, or "
            "AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1 for local development only."
        )
    elif not auth_configured:
        _logger.warning(
            "SECURITY: AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1 enables unauthenticated API access. "
            "Use only for single-user local development."
        )


def _apply_worker_thread_limit() -> None:
    """Cap offloaded worker threads so they cannot outrun the connection pool.

    AnyIO's default limiter is per-event-loop, so this runs at startup inside
    the running loop rather than at import time.
    """
    import anyio.to_thread

    anyio.to_thread.current_default_thread_limiter().total_tokens = _config.WORKER_THREAD_LIMIT


def _validate_configured_registries() -> None:
    if not env_raw("SNOWFLAKE_ACCOUNT") and postgres_deployment_configured():
        from agent_bom.api.storage.registry_stores import validate_postgres_registries

        validate_postgres_registries()


def _preflight_postgres_tenant_isolation() -> None:
    """Fail bare ASGI startup before traffic when the DB role can bypass RLS."""
    # Store selection is Snowflake > Postgres > SQLite. A dormant Postgres URL
    # must not load an optional driver or contact an unused backend when the
    # selected Snowflake control plane starts.
    if env_raw("SNOWFLAKE_ACCOUNT") or not postgres_deployment_configured():
        return
    from agent_bom.api.postgres_common import preflight_rls_capable_role

    preflight_rls_capable_role()


def _initialize_snowflake() -> None:
    from agent_bom.api.snowflake_store import (
        SnowflakeExceptionStore,
        SnowflakeFleetStore,
        SnowflakePolicyStore,
        SnowflakeScheduleStore,
        build_connection_params,
    )

    sf = build_connection_params()
    if _stores._store is None:
        _stores._get_store()
    if _stores._fleet_store is None:
        set_fleet_store(SnowflakeFleetStore(sf))
    if _stores._policy_store is None:
        set_policy_store(SnowflakePolicyStore(sf))
    if _stores._schedule_store is None:
        set_schedule_store(SnowflakeScheduleStore(sf))
    if _stores._exception_store is None:
        set_exception_store(SnowflakeExceptionStore(sf))


def _initialize_postgres() -> None:
    from agent_bom.api import audit_log as _audit_log_mod
    from agent_bom.api import auth as _auth
    from agent_bom.api import cost_store as _cost_store_mod
    from agent_bom.api.audit_log import set_audit_log
    from agent_bom.api.auth import set_key_store
    from agent_bom.api.cost_store import set_cost_store
    from agent_bom.api.postgres_store import (
        PostgresAuditLog,
        PostgresCostStore,
        PostgresCredentialRefStore,
        PostgresExceptionStore,
        PostgresFleetStore,
        PostgresGraphStore,
        PostgresKeyStore,
        PostgresPolicyStore,
        PostgresSourceStore,
        PostgresTrendStore,
    )

    if _stores._store is None:
        _stores._get_store()
    if _cost_store_mod._COST_STORE is None:
        set_cost_store(PostgresCostStore())
    if _stores._fleet_store is None:
        set_fleet_store(PostgresFleetStore())
    if _stores._policy_store is None:
        set_policy_store(PostgresPolicyStore())
    if _stores._source_store is None:
        set_source_store(PostgresSourceStore())
    if _stores._credential_ref_store is None:
        set_credential_ref_store(PostgresCredentialRefStore())
    if _stores._exception_store is None:
        set_exception_store(PostgresExceptionStore())
    if _stores._trend_store is None:
        set_trend_store(PostgresTrendStore())
    if _stores._graph_store is None:
        set_graph_store(PostgresGraphStore())
    if _auth._key_store is None:
        set_key_store(PostgresKeyStore())
    if _audit_log_mod._audit_log is None:
        set_audit_log(PostgresAuditLog())


def _initialize_sqlite() -> None:
    from agent_bom.api import audit_log as _audit_log_mod
    from agent_bom.api.audit_log import SQLiteAuditLog, set_audit_log

    db_path = env_raw("AGENT_BOM_DB", "")
    if _stores._store is None:
        _stores._get_store()
    if _stores._fleet_store is None:
        from agent_bom.api.fleet_store import SQLiteFleetStore

        set_fleet_store(SQLiteFleetStore(db_path))
    if _stores._policy_store is None:
        from agent_bom.api.policy_store import SQLitePolicyStore

        set_policy_store(SQLitePolicyStore(db_path))
    if _stores._source_store is None:
        from agent_bom.api.source_store import SQLiteSourceStore

        set_source_store(SQLiteSourceStore(db_path))
    if _stores._credential_ref_store is None:
        from agent_bom.api.credential_store import SQLiteCredentialRefStore

        set_credential_ref_store(SQLiteCredentialRefStore(db_path))
    if _stores._trend_store is None:
        from agent_bom.baseline import SQLiteTrendStore

        set_trend_store(SQLiteTrendStore(db_path))
    if _stores._graph_store is None:
        from agent_bom.api.graph_store import SQLiteGraphStore

        set_graph_store(SQLiteGraphStore())
    if _audit_log_mod._audit_log is None:
        set_audit_log(SQLiteAuditLog(db_path))


def _initialize_companion_stores(snowflake_configured: bool) -> None:
    if _stores._source_store is None:
        if postgres_deployment_configured() and not snowflake_configured:
            from agent_bom.api.postgres_store import PostgresSourceStore

            set_source_store(PostgresSourceStore())
        elif env_raw("AGENT_BOM_DB"):
            from agent_bom.api.source_store import SQLiteSourceStore

            set_source_store(SQLiteSourceStore(env_raw("AGENT_BOM_DB", "")))
        else:
            from agent_bom.api.source_store import InMemorySourceStore

            set_source_store(InMemorySourceStore())

    if _stores._credential_ref_store is None:
        if postgres_deployment_configured() and not snowflake_configured:
            from agent_bom.api.postgres_store import PostgresCredentialRefStore

            set_credential_ref_store(PostgresCredentialRefStore())
        elif env_raw("AGENT_BOM_DB"):
            from agent_bom.api.credential_store import SQLiteCredentialRefStore

            set_credential_ref_store(SQLiteCredentialRefStore(env_raw("AGENT_BOM_DB", "")))
        else:
            from agent_bom.api.credential_store import InMemoryCredentialRefStore

            set_credential_ref_store(InMemoryCredentialRefStore())

    # Skills results share Postgres when configured; Snowflake needs a companion.
    from agent_bom.api.skills_scan_store import SkillsPersistenceUnavailableError, get_skills_scan_store

    try:
        get_skills_scan_store()
    except SkillsPersistenceUnavailableError:
        _logger.warning("Skills result persistence unavailable: configure a supported Postgres or SQLite store")

    # ── Schedule store ──
    if _stores._schedule_store is None:
        if postgres_deployment_configured() and not snowflake_configured:
            from agent_bom.api.postgres_store import PostgresScheduleStore

            set_schedule_store(PostgresScheduleStore())
        elif env_raw("AGENT_BOM_DB"):
            from agent_bom.api.schedule_store import SQLiteScheduleStore

            set_schedule_store(SQLiteScheduleStore(env_raw("AGENT_BOM_DB", "")))
        else:
            from agent_bom.api.schedule_store import InMemoryScheduleStore

            set_schedule_store(InMemoryScheduleStore())


def _initialize_analytics() -> None:
    # ── Analytics store (ClickHouse OLAP — optional) ──
    analytics_backend, clickhouse_url = _analytics_backend_config()
    if analytics_backend == "clickhouse" and peek_analytics_store() is None:
        try:
            from agent_bom.api.clickhouse_store import BufferedAnalyticsStore, ClickHouseAnalyticsStore

            if not clickhouse_url:
                raise ValueError("ClickHouse analytics backend requires AGENT_BOM_CLICKHOUSE_URL")
            base_store = ClickHouseAnalyticsStore(url=clickhouse_url)
            if env_raw("AGENT_BOM_CLICKHOUSE_BUFFERED", "1").strip().lower() not in {"0", "false", "no"}:
                flush_interval = float(env_raw("AGENT_BOM_CLICKHOUSE_FLUSH_INTERVAL", "1.0"))
                max_batch = int(env_raw("AGENT_BOM_CLICKHOUSE_MAX_BATCH", "200"))
                max_queue = int(env_raw("AGENT_BOM_CLICKHOUSE_MAX_QUEUE", "10000"))
                set_analytics_store(
                    BufferedAnalyticsStore(
                        base_store,
                        flush_interval=flush_interval,
                        max_batch=max_batch,
                        max_queue=max_queue,
                    )
                )
                _logger.info(
                    "ClickHouse analytics store enabled with buffered writes (batch=%s, queue=%s, flush_interval=%.2fs)",
                    max_batch,
                    max_queue,
                    flush_interval,
                )
            else:
                set_analytics_store(base_store)
                _logger.info("ClickHouse analytics store enabled without buffering")
        except Exception:
            _logger.warning("ClickHouse analytics unavailable, using NullAnalyticsStore", exc_info=False)


def initialize_storage() -> None:
    """Initialize unset stores, preserving backend precedence and injected stores."""
    snowflake_configured = bool(env_raw("SNOWFLAKE_ACCOUNT"))
    if snowflake_configured:
        _initialize_snowflake()
    elif env_raw("AGENT_BOM_GRAPH_BACKEND", "").strip().lower() == "neptune":
        from agent_bom.api.neptune_graph import NeptuneGraphStore

        if _stores._graph_store is None:
            set_graph_store(NeptuneGraphStore())
    elif postgres_deployment_configured():
        _initialize_postgres()
    elif env_raw("AGENT_BOM_DB"):
        _initialize_sqlite()
    _initialize_companion_stores(snowflake_configured)
    _initialize_analytics()
