"""Immutable first Postgres schema for the evidence registries."""

REGISTRY_TABLES = {
    "kspm_cluster_posture": "run_id TEXT NOT NULL, cluster_ref TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,run_id)",
    "mcp_observations": "observation_id TEXT NOT NULL, server_canonical_id TEXT NOT NULL, server_name TEXT NOT NULL, "
    "updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, observation_id)",
    "skills_scan_run": "run_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, run_id)",
    "issue_mappings": "mapping_id TEXT NOT NULL, target_kind TEXT NOT NULL, target_id TEXT NOT NULL, provider TEXT NOT NULL, "
    "PRIMARY KEY (tenant_id, mapping_id), UNIQUE(tenant_id,target_kind,target_id,provider)",
    "dataset_versions": "dataset_id TEXT NOT NULL, version_id TEXT NOT NULL, created_at TEXT NOT NULL, "
    "PRIMARY KEY (tenant_id, dataset_id, version_id)",
    "evaluation_runs": "evaluation_id TEXT NOT NULL, dataset_id TEXT, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, evaluation_id)",
    "webhook_subscriptions": "subscription_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, "
    "PRIMARY KEY (tenant_id, subscription_id)",
    "drift_incidents": "incident_id TEXT NOT NULL, resolved BOOLEAN NOT NULL, last_detected_at TEXT NOT NULL, "
    "PRIMARY KEY (tenant_id, incident_id)",
}

# Match key for open-incident lookups by (tenant, blueprint); mirrors
# ``drift_incident_store.drift_blueprint_key``. Must stay byte-identical to the
# expression in the index below (and its Alembic revision 20261024_01).
DRIFT_BLUEPRINT_KEY_SQL = r"lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))"
DRIFT_BLUEPRINT_OPEN_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_drift_incidents_tenant_blueprint_open ON public.drift_incidents "
    f"(tenant_id, ({DRIFT_BLUEPRINT_KEY_SQL}), last_detected_at DESC) WHERE NOT resolved"
)


def registry_table_ddl(table: str) -> str:
    return (
        f"CREATE TABLE IF NOT EXISTS public.{table} ("
        "tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, "
        f"{REGISTRY_TABLES[table]})"
    )


def registry_migration_ddl() -> str:
    statements = []
    for table in REGISTRY_TABLES:
        statements.extend(
            [
                registry_table_ddl(table),
                f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant ON public.{table} (tenant_id)",
                f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY",
                f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY",
                f"DROP POLICY IF EXISTS {table}_tenant_isolation ON public.{table}",
                f"CREATE POLICY {table}_tenant_isolation ON public.{table} "
                "USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) "
                "WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())",
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO agent_bom_app, agent_bom_rls_maintenance",
                "INSERT INTO control_plane_schema_versions(component,version,updated_at) "  # nosec B608 - table comes only from REGISTRY_TABLES
                f"VALUES ('{table}',1,now()) ON CONFLICT(component) DO UPDATE SET "
                "version=GREATEST(control_plane_schema_versions.version,1)",
            ]
        )
    return ";\n".join(statements) + ";"
