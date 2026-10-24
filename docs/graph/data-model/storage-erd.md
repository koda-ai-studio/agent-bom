# Storage ERD

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Every table agent-bom creates, read from the DDL in the code: the Postgres control-plane schema (bootstrap SQL and Alembic revisions), the stores' own bootstrap DDL for Postgres and SQLite, the ClickHouse analytics schema and the Snowflake schema. Back to the [data model](../DATA_MODEL.md).

## Overview

160 tables in 10 domains. 18 declared foreign keys; 36 logical joins derived from shared key-column names. Arrows count relations that cross domains.

```mermaid
flowchart LR
  tenancy["Tenancy, identity and access<br/>24 tables"]
  scans["Scans, jobs and reports<br/>15 tables"]
  inventory["Inventory and assets<br/>16 tables"]
  findings["Findings, triage and VEX<br/>25 tables"]
  graph["Graph nodes, edges, snapshots and attack paths<br/>21 tables"]
  runtime["Runtime, gateway and traces<br/>17 tables"]
  compliance["Compliance, audit and evidence<br/>10 tables"]
  connectors["Connectors, delivery and schedules<br/>16 tables"]
  vulndb["Vulnerability intelligence (local database)<br/>7 tables"]
  other["Schema metadata and maintenance<br/>9 tables"]
  runtime -- "1 FK" --> compliance
  scans -- "2 FK" --> compliance
  scans -- "2 FK" --> findings
  scans -- "2 FK" --> inventory
  tenancy -- "2 FK" --> compliance
  tenancy -- "2 FK" --> findings
  tenancy -- "1 FK" --> inventory
  tenancy -- "2 FK" --> scans
```

| Domain | Tables | Page |
|---|---|---|
| Tenancy, identity and access | 24 | [storage-erd/tenancy.md](storage-erd/tenancy.md) |
| Scans, jobs and reports | 15 | [storage-erd/scans.md](storage-erd/scans.md) |
| Inventory and assets | 16 | [storage-erd/inventory.md](storage-erd/inventory.md) |
| Findings, triage and VEX | 25 | [storage-erd/findings.md](storage-erd/findings.md) |
| Graph nodes, edges, snapshots and attack paths | 21 | [storage-erd/graph.md](storage-erd/graph.md) |
| Runtime, gateway and traces | 17 | [storage-erd/runtime.md](storage-erd/runtime.md) |
| Compliance, audit and evidence | 10 | [storage-erd/compliance.md](storage-erd/compliance.md) |
| Connectors, delivery and schedules | 16 | [storage-erd/connectors.md](storage-erd/connectors.md) |
| Vulnerability intelligence (local database) | 7 | [storage-erd/vulndb.md](storage-erd/vulndb.md) |
| Schema metadata and maintenance | 9 | [storage-erd/other.md](storage-erd/other.md) |

## How relations are derived

- **Declared** (solid line): a `REFERENCES` clause or `FOREIGN KEY` constraint in the DDL.
- **Logical** (dashed line, labelled `logical`): tables in the same domain and backend family share a key column with an owning table. The owner is the target of a declared foreign key on that column name, or the one table whose primary key is that column (apart from the tenant column). Generic names (`entry_id`, `event_id`, `item_id`, `result_id`, `row_id`, `run_id`, `source_id`, `version_id`) join only between tables that share a name stem. Logical joins are not enforced by the database.
- Tenant columns (`tenant_id`, `team_id`) scope every row to a tenant and are part of every logical join where both tables carry one; they are shown as columns, not drawn as relations.
- Diagrams show key columns only: primary key, foreign keys, tenant, `scan_id`, canonical/stable ids and logical join columns.

## Sources

| Source | Dialect |
|---|---|
| `deploy/supabase/postgres/init.sql` | Postgres |
| `deploy/supabase/postgres/runtime-schema.sql` | Postgres |
| `deploy/supabase/postgres/alembic/versions/` | Postgres |
| `deploy/supabase/clickhouse/init.sql` | ClickHouse |
| `deploy/snowflake/setup.sql` | Snowflake |
| `deploy/snowflake/native-app/dcm/V001__core_schema.sql` | Snowflake |
| `deploy/snowflake/native-app/dcm/V003__fleet_endpoints.sql` | Snowflake |
| `src/agent_bom/**/*.py` string literals | ClickHouse, Snowflake, SQLite or Postgres, from the module path, the enclosing class/function name, dialect-only syntax, and whether the module imports `sqlite3` |

Excluded:

- `src/agent_bom/export/destinations.py`: creates tables in a customer-owned export destination, not in agent-bom's store
- `src/agent_bom/api/partition_maintenance.py`: generic partition builders; the parent tables are defined by their owning stores

## Table index

| Table | Domain | Backends | Primary key | Key columns | Tenant column | Lifetime | Defined in |
|---|---|---|---|---|---|---|---|
| `access_review_campaigns` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `tenant_id`, `campaign_id` | `campaign_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/access_review.py`, `api/postgres_access_review.py` |
| `access_review_items` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `tenant_id`, `item_id` | `item_id`, `campaign_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/access_review.py`, `api/postgres_access_review.py` |
| `adoption_events` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `id` | `id` | **none** | persistent | `db/adoption_events.py` |
| `affected` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `vuln_id`, `ecosystem`, `package_name`, `introduced`, `fixed`, `last_affected`, `limit_version` | `vuln_id`, `ecosystem`, `package_name`, `introduced`, `fixed`, `last_affected`, `limit_version` | **none** | persistent | `db/schema.py` |
| `agent_bom_hub_backfills` | [Schema metadata and maintenance](storage-erd/other.md) | Postgres | `name` | `name` | **none** | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_compliance_hub.py` |
| `agent_bom_snapshots` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `snapshot_id` | `tenant_id`, `snapshot_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_01_agent_lifecycle.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/lifecycle_store.py` |
| `agent_bom_tenant_access` | [Tenancy, identity and access](storage-erd/tenancy.md) | Snowflake | `tenant_id`, `snowflake_role` | `tenant_id`, `snowflake_role` | `tenant_id` | persistent | `api/snowflake_store.py` |
| `agent_bom_tenant_binding_keys` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `key_id` | `key_id` | **none** | persistent | `deploy/supabase/postgres/alembic/versions/20260819_01_tenant_binding_authority.py`, `deploy/supabase/postgres/init.sql`, `deploy/supabase/postgres/runtime-schema.sql` |
| `agent_conditional_access_policies` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `policy_id` | `policy_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/identity_local_store.py`, `api/postgres_agent_identity.py` |
| `agent_identities` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `identity_id` | `identity_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/identity_local_store.py`, `api/postgres_agent_identity.py` |
| `agent_identity_jit_grants` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `grant_id` | `grant_id`, `tenant_id`, `identity_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/identity_local_store.py`, `api/postgres_agent_identity.py` |
| `agent_lifecycle_records` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `kind`, `record_id` | `tenant_id`, `kind`, `record_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_01_agent_lifecycle.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/lifecycle_store.py` |
| `agents` | [Inventory and assets](storage-erd/inventory.md) | Postgres | `agent_id` | `agent_id`, `scan_run_id`, `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql` |
| `ai_system_blueprint_versions` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `blueprint_id`, `version` | `tenant_id`, `blueprint_id`, `version` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/blueprint_store.py`, `api/postgres_blueprint.py` |
| `ai_system_blueprints` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `blueprint_id` | `tenant_id`, `blueprint_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/blueprint_store.py`, `api/postgres_blueprint.py` |
| `api_keys` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `key_id` | `key_id`, `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_access.py` |
| `api_rate_limit_hits` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | — | `bucket_key` | **none** | persistent | `deploy/supabase/postgres/init.sql`, `api/rate_limit_store.py` |
| `api_rate_limits` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `bucket_key`, `window_started` | `bucket_key`, `window_started` | **none** | persistent | `deploy/supabase/postgres/init.sql` |
| `assets` | [Inventory and assets](storage-erd/inventory.md) | SQLite | `tenant_id`, `vuln_id`, `package`, `ecosystem` | `tenant_id`, `vuln_id`, `package`, `ecosystem` | `tenant_id` | persistent | `asset_tracker.py` |
| `attack_paths` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `tenant_id`, `scan_id`, `path_key` | `scan_id`, `tenant_id`, `path_key` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py`, `db/graph_store_schema.py` |
| `attestation_replay` | [Compliance, audit and evidence](storage-erd/compliance.md) | SQLite | `tenant_id`, `evidence_id`, `nonce` | `tenant_id`, `evidence_id`, `nonce` | `tenant_id` | persistent | `sbom_attestation.py` |
| `audit_chain_checkpoint` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/audit_log.py`, `api/postgres_audit.py` |
| `audit_events` | [Compliance, audit and evidence](storage-erd/compliance.md) | ClickHouse | `tenant_id`, `entry_id` | `entry_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `audit_log` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, SQLite | `entry_id` | `entry_id`, `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/audit_log.py`, `api/postgres_audit.py` |
| `auth_session_attempts` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | — | `key` | **none** | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/shared_auth_state.py` |
| `bound_references` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Snowflake | `reference_name`, `object_name` | `reference_name`, `object_name` | **none** | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql` |
| `campaign_evidence_state` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/storage/campaign_revisions.py`, `api/storage/campaign_schema.py` |
| `cis_benchmark_checks` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, ClickHouse | `id` | `id`, `scan_id`, `team_id` | `team_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `deploy/supabase/postgres/init.sql`, `api/postgres_job_store.py` (+1) |
| `cloud_connections` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `id` | `id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/connection_store.py`, `api/postgres_connection.py` |
| `compliance_controls` | [Compliance, audit and evidence](storage-erd/compliance.md) | ClickHouse | `tenant_id`, `scan_id`, `control_key` | `scan_id`, `tenant_id`, `control_key` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `compliance_hub_findings` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite, Snowflake | `tenant_id`, `finding_id` | `tenant_id`, `finding_id`, `scan_id` | `tenant_id` | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql`, `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_compliance_hub.py` (+1) |
| `compliance_hub_findings_v2` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `tenant_id`, `finding_id` | `tenant_id`, `finding_id`, `scan_id` | `tenant_id` | persistent | `api/storage/hub_schema.py` |
| `control_plane_schema_versions` | [Schema metadata and maintenance](storage-erd/other.md) | Postgres, SQLite, ClickHouse | `component` | `component` | **none** | persistent | `deploy/supabase/clickhouse/init.sql`, `deploy/supabase/postgres/alembic/versions/20260825_01_graph_scenarios.py`, `deploy/supabase/postgres/runtime-schema.sql` (+2) |
| `control_plane_sources` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres | `source_id` | `source_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/source_postgres.py` |
| `cpe_matches` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `cve_id`, `criteria`, `version_start`, `version_end` | `cve_id`, `criteria`, `version_start`, `version_end` | **none** | persistent | `db/schema.py` |
| `credential_refs` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `credential_ref_id` | `credential_ref_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/credential_store.py`, `api/postgres_policy.py` |
| `dataset_versions` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `dataset_id`, `version_id` | `tenant_id`, `dataset_id`, `version_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/dataset_version_store.py`, `api/storage/registry_schema.py` |
| `delivery_breaker` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `destination_id` | `destination_id` | **none** | persistent | `delivery.py` |
| `delivery_ledger` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `destination_id`, `idempotency_key` | `idempotency_key`, `destination_id` | **none** | persistent | `delivery.py` |
| `delivery_log` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `id` | `id` | **none** | persistent | `delivery.py` |
| `delta_stream_watermarks` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `tenant_id`, `destination_id` | `tenant_id`, `destination_id` | `tenant_id` | persistent | `delta_stream.py` |
| `device_posture` | [Inventory and assets](storage-erd/inventory.md) | SQLite | `tenant_id`, `device_id` | `tenant_id`, `device_id` | `tenant_id` | persistent | `device_posture.py` |
| `drift_incidents` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `incident_id` | `tenant_id`, `incident_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/drift_incident_store.py`, `api/storage/registry_schema.py` |
| `edge_groups` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `source_type`, `source_identity`, `target_type`, `target_identity`, `relationship` | `source_type`, `source_identity`, `target_type`, `target_identity`, `relationship` | **none** | scratch | `graph/correlation_workspace.py` |
| `edge_observations` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `source_type`, `source_identity`, `target_type`, `target_identity`, `relationship`, `scan_id`, `edge_id` | `source_type`, `source_identity`, `target_type`, `target_identity`, `relationship`, `scan_id`, `edge_id` | **none** | scratch | `graph/correlation_workspace.py` |
| `endpoint_agent_bindings` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `device_id`, `agent_id` | `tenant_id`, `device_id`, `agent_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py`, `connectors/endpoints/store.py` |
| `endpoint_connections` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres | `tenant_id`, `id` | `tenant_id`, `id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py`, `connectors/endpoints/store.py` |
| `endpoint_devices` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `connection_id`, `run_id`, `device_id` | `tenant_id`, `connection_id`, `run_id`, `device_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py`, `connectors/endpoints/store.py` |
| `endpoint_sync_events` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `tenant_id`, `connection_id`, `event_id` | `tenant_id`, `connection_id`, `event_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py`, `connectors/endpoints/store.py` |
| `endpoint_syncs` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `tenant_id`, `connection_id`, `run_id` | `tenant_id`, `connection_id`, `run_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py`, `connectors/endpoints/store.py` |
| `epss_scores` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `cve_id` | `cve_id` | **none** | persistent | `db/schema.py` |
| `evaluation_runs` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, SQLite | `tenant_id`, `evaluation_id` | `tenant_id`, `evaluation_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/evaluation_store.py`, `api/storage/registry_schema.py` |
| `exceptions` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite, Snowflake | `exception_id` | `exception_id`, `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/exception_store.py`, `api/postgres_access.py` (+1) |
| `export_destinations` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `tenant_id`, `id` | `id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260923_01_export_destinations.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/export_destination_store.py` |
| `export_schedules` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `tenant_id`, `schedule_id` | `schedule_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260929_02_export_schedules.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/export_schedule_store.py` (+1) |
| `finding_history_jobs` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres | `tenant_id`, `job_id` | `tenant_id`, `job_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/storage/finding_history_schema.py` |
| `finding_history_rows` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres | `tenant_id`, `job_id`, `ordinal` | `tenant_id`, `job_id`, `ordinal` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/storage/finding_history_schema.py` |
| `findings` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres | `finding_id` | `finding_id`, `scan_run_id`, `team_id`, `cve_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql` |
| `findings_by_framework` | [Findings, triage and VEX](storage-erd/findings.md) | Snowflake | `finding_id`, `framework_slug` | `finding_id`, `framework_slug`, `tenant_id` | `tenant_id` | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql` |
| `findings_feed` | [Findings, triage and VEX](storage-erd/findings.md) | ClickHouse | `tenant_id`, `finding_id` | `tenant_id`, `run_id`, `finding_id`, `canonical_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `findings_feed_runs` | [Findings, triage and VEX](storage-erd/findings.md) | ClickHouse | `tenant_id`, `run_id` | `tenant_id`, `run_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `findings_feed_staged` | [Findings, triage and VEX](storage-erd/findings.md) | ClickHouse | `tenant_id`, `run_id`, `publication_attempt_id`, `finding_id` | `tenant_id`, `run_id`, `publication_attempt_id`, `finding_id`, `canonical_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `fleet_agents` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite, Snowflake, ClickHouse | `tenant_id`, `agent_id` | `agent_id`, `tenant_id`, `canonical_id` | `tenant_id` | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql`, `deploy/snowflake/setup.sql`, `deploy/supabase/clickhouse/init.sql` (+5) |
| `fleet_agents_tenant_key_migration` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `tenant_id`, `agent_id` | `agent_id`, `canonical_id`, `tenant_id` | `tenant_id` | persistent | `api/fleet_store.py` |
| `fleet_endpoints` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite, Snowflake | `tenant_id`, `endpoint_id` | `tenant_id`, `endpoint_id` | `tenant_id` | persistent | `deploy/snowflake/native-app/dcm/V003__fleet_endpoints.sql`, `deploy/snowflake/setup.sql`, `deploy/supabase/postgres/init.sql` (+4) |
| `gateway_activity_events` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `event_id` | `tenant_id`, `event_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260728_02_gateway_activity_ledger.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/gateway_activity_store.py` |
| `gateway_activity_sequences` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260728_02_gateway_activity_ledger.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/gateway_activity_store.py` |
| `gateway_activity_tombstones` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `event_id` | `tenant_id`, `event_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260728_02_gateway_activity_ledger.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/gateway_activity_store.py` |
| `gateway_policies` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite, Snowflake | `policy_id` | `policy_id`, `team_id` | `team_id` | persistent | `deploy/snowflake/setup.sql`, `deploy/supabase/postgres/init.sql`, `api/policy_store.py` (+2) |
| `governance_audit_log` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, SQLite | `seq` | `seq`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/governance_audit_log.py`, `api/postgres_governance_audit.py` |
| `graph_attack_paths` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `tenant_id`, `scan_id`, `path_key` | `tenant_id`, `scan_id`, `path_key` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261013_01_graph_attack_paths.py`, `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py` (+1) |
| `graph_build_workspace_edges` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres | `workspace_id`, `tenant_id`, `edge_key` | `workspace_id`, `tenant_id`, `edge_key` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260720_03_graph_build_workspace.py`, `deploy/supabase/postgres/init.sql` |
| `graph_build_workspace_nodes` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres | `workspace_id`, `tenant_id`, `node_id` | `workspace_id`, `tenant_id`, `node_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260720_03_graph_build_workspace.py`, `deploy/supabase/postgres/init.sql` |
| `graph_correlation_runs` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `correlation_id`, `tenant_id` | `correlation_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260830_01_graph_correlations.py`, `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py` (+1) |
| `graph_edges` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `source_id`, `target_id`, `relationship`, `scan_id`, `tenant_id` | `source_id`, `target_id`, `relationship`, `scan_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py`, `db/graph_store_schema.py` |
| `graph_filter_presets` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres | `name`, `tenant_id` | `name`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/graph_store_support.py`, `api/postgres_graph_schema.py` |
| `graph_node_aliases` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `tenant_id`, `alias_id` | `tenant_id`, `alias_id`, `canonical_id`, `scan_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261014_01_graph_node_aliases.py`, `deploy/supabase/postgres/init.sql`, `api/postgres_graph_aliases.py` (+1) |
| `graph_node_search` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres | `node_id`, `scan_id`, `tenant_id` | `node_id`, `tenant_id`, `scan_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py` |
| `graph_nodes` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `id`, `scan_id`, `tenant_id` | `id`, `scan_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py`, `db/graph_store_schema.py` |
| `graph_retention_state` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `id` | `id` | **none** | persistent | `db/graph_store_schema.py` |
| `graph_scenarios` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `id`, `tenant_id` | `id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260825_01_graph_scenarios.py`, `deploy/supabase/postgres/init.sql`, `deploy/supabase/postgres/runtime-schema.sql` (+2) |
| `graph_schema_version` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `version` | `version` | **none** | persistent | `db/graph_store_schema.py` |
| `graph_snapshots` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `scan_id`, `tenant_id` | `scan_id`, `tenant_id`, `correlation_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py`, `db/graph_store_schema.py` |
| `hitl_approvals` | [Findings, triage and VEX](storage-erd/findings.md) | SQLite | `item_id` | `item_id`, `tenant_id` | `tenant_id` | persistent | `api/hitl_approval_store.py` |
| `hub_cve_intel` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `cve_id` | `tenant_id`, `cve_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/hub_reference_store.py` |
| `hub_findings_current` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres | `tenant_id`, `canonical_id` | `tenant_id`, `canonical_id`, `scan_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/finding_lifecycle.py` |
| `hub_findings_current_observations` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `canonical_id`, `scan_id` | `tenant_id`, `canonical_id`, `scan_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/finding_lifecycle.py`, `api/hub_observations_partition.py` (+2) |
| `hub_framework_refs` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres, SQLite | `tenant_id`, `framework_ref` | `tenant_id`, `framework_ref` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/hub_reference_store.py` |
| `hub_ledger_ingest_state` | [Findings, triage and VEX](storage-erd/findings.md) | SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `api/storage/finding_ingest_state.py` |
| `hub_overview_revisions` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260827_01_hub_overview_revision.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_compliance_hub.py` (+1) |
| `idempotency_keys` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `endpoint`, `tenant_id`, `source_id`, `idempotency_key` | `endpoint`, `tenant_id`, `source_id`, `idempotency_key` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260903_01_execution_leases.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/idempotency_store.py` |
| `interaction_risks` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | Postgres, SQLite | `pattern`, `agents`, `scan_id`, `tenant_id` | `pattern`, `agents`, `scan_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_graph_schema.py`, `db/graph_store_schema.py` |
| `issue_mappings` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `mapping_id` | `tenant_id`, `mapping_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/issue_mapping_store.py`, `api/storage/registry_schema.py` |
| `job_overview_identity` | [Scans, jobs and reports](storage-erd/scans.md) | SQLite | `singleton` | `singleton` | **none** | persistent | `api/store.py` |
| `job_overview_revisions` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/storage/job_revisions.py`, `api/store.py` |
| `job_queue` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres | `job_id` | `job_id`, `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql` |
| `jobs` | [Scans, jobs and reports](storage-erd/scans.md) | SQLite | `job_id` | `job_id`, `tenant_id`, `schedule_id` | `tenant_id` | persistent | `api/store.py` |
| `kev_entries` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `cve_id` | `cve_id` | **none** | persistent | `db/schema.py` |
| `kspm_cluster_posture` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `run_id` | `tenant_id`, `run_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/kspm_posture_store.py`, `api/storage/registry_schema.py` |
| `llm_cost_budgets` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `agent`, `cost_center`, `owner`, `workflow` | `tenant_id`, `agent`, `cost_center`, `owner`, `workflow` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/cost_store.py`, `api/postgres_cost.py` |
| `llm_costs` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `call_id` | `tenant_id`, `call_id`, `session_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/cost_store.py`, `api/postgres_cost.py` |
| `local_schema_meta` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | `component` | `component` | **none** | persistent | `db/local_analytics.py` |
| `managed_trial_invitations` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `invitation_id` | `invitation_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260724_03_managed_trial_invitations.py`, `deploy/supabase/postgres/runtime-schema.sql` |
| `managed_trial_tenants` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260724_03_managed_trial_invitations.py`, `deploy/supabase/postgres/runtime-schema.sql` |
| `mcp_client_configs` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `config_id` | `config_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/mcp_config_store.py`, `api/postgres_mcp_config.py` |
| `mcp_observations` | [Inventory and assets](storage-erd/inventory.md) | Postgres, SQLite | `tenant_id`, `observation_id` | `tenant_id`, `observation_id`, `server_canonical_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/mcp_observation_store.py`, `api/storage/registry_schema.py` |
| `mcp_scan_results` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres | `tenant_id`, `result_id` | `tenant_id`, `result_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260927_02_mcp_scan_results.py`, `deploy/supabase/postgres/runtime-schema.sql`, `mcp_tools/result_store.py` |
| `merged_nodes` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `entity_type`, `identity` | `entity_type`, `identity` | **none** | scratch | `graph/correlation_workspace.py` |
| `model_provider_keys` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `provider_key_id` | `provider_key_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/model_key_broker.py`, `api/postgres_model_key_broker.py` |
| `model_virtual_keys` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `virtual_key_id` | `virtual_key_id`, `tenant_id`, `provider_key_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/model_key_broker.py`, `api/postgres_model_key_broker.py` |
| `node_groups` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `entity_type`, `identity` | `entity_type`, `identity` | **none** | scratch | `graph/correlation_workspace.py` |
| `node_observations` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `entity_type`, `identity`, `scan_id`, `node_id` | `entity_type`, `identity`, `scan_id`, `node_id` | **none** | scratch | `graph/correlation_workspace.py` |
| `operator_advisories` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `advisory_id` | `tenant_id`, `advisory_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261023_01_operator_advisories.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/operator_advisory_store.py` (+1) |
| `operator_advisory_rematch_state` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261023_01_operator_advisories.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/operator_advisory_store.py` (+1) |
| `osv_cache` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | Postgres, SQLite | `cache_key` | `cache_key` | **none** | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_scan_cache.py`, `scan_cache.py` |
| `policy_audit_log` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite, Snowflake | `id` | `id`, `team_id` | `team_id` | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql`, `deploy/snowflake/setup.sql`, `deploy/supabase/postgres/init.sql` (+3) |
| `policy_results` | [Compliance, audit and evidence](storage-erd/compliance.md) | Postgres | `result_id` | `result_id`, `scan_run_id`, `team_id`, `policy_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql` |
| `posture_scores` | [Runtime, gateway and traces](storage-erd/runtime.md) | ClickHouse | `measured_at`, `agent_name` | `measured_at`, `tenant_id`, `agent_name` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `posture_webhook_outbox` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `id` | `id`, `tenant_id` | `tenant_id` | persistent | `posture_streaming.py` |
| `proxy_replay_log` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `row_id` | `row_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/proxy_replay_store.py` |
| `report_jobs` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres | `tenant_id`, `job_id` | `job_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260911_01_durable_report_jobs.py`, `api/report_job_store.py` |
| `revoked_session_nonces` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `nonce` | `nonce` | **none** | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/shared_auth_state.py` |
| `risk_campaign_workflows` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `tenant_id`, `campaign_id` | `tenant_id`, `campaign_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/campaign_store.py`, `api/postgres_campaign.py` |
| `runtime_events` | [Runtime, gateway and traces](storage-erd/runtime.md) | ClickHouse | `tenant_id`, `event_id` | `event_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `runtime_observation_revisions` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres | `tenant_id`, `observation_id`, `revision` | `tenant_id`, `observation_id`, `revision` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261012_03_runtime_trace_revisions.py`, `api/storage/runtime_trace_revisions.py` |
| `runtime_observations` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `observation_id` | `tenant_id`, `observation_id`, `session_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_runtime_event.py`, `api/runtime_event_store.py` |
| `runtime_sessions` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `session_id` | `tenant_id`, `session_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_runtime_event.py`, `api/runtime_event_store.py` |
| `runtime_trace_imports` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres | `tenant_id`, `import_id` | `tenant_id`, `import_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20261012_02_runtime_trace_imports.py`, `api/storage/runtime_trace_imports.py` |
| `runtime_workload_evidence` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres, SQLite | `tenant_id`, `provider`, `account_id`, `workload_ref`, `dedup_key` | `tenant_id`, `provider`, `account_id`, `workload_ref`, `dedup_key` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260724_01_runtime_workload_evidence_authority.py`, `deploy/supabase/postgres/runtime-schema.sql`, `cloud/runtime_workload_evidence_store.py` |
| `scan_dispatch_queue` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres | `tenant_id`, `job_id` | `job_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260728_03_trusted_maintenance_rls.py`, `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_job_store.py` |
| `scan_findings` | [Findings, triage and VEX](storage-erd/findings.md) | SQLite | `run_id`, `finding_key` | `run_id`, `scan_id`, `finding_key`, `canonical_id`, `asset_canonical_id` | **none** | persistent | `db/local_analytics.py` |
| `scan_jobs` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, Snowflake | `team_id`, `job_id` | `job_id`, `team_id`, `schedule_id` | `team_id` | persistent | `deploy/snowflake/native-app/dcm/V001__core_schema.sql`, `deploy/snowflake/setup.sql`, `deploy/supabase/postgres/init.sql` (+2) |
| `scan_metadata` | [Scans, jobs and reports](storage-erd/scans.md) | ClickHouse | `tenant_id`, `scan_id` | `scan_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `scan_packages` | [Inventory and assets](storage-erd/inventory.md) | SQLite | `run_id`, `agent_name`, `server_name`, `package_name`, `package_version`, `ecosystem` | `run_id`, `scan_id`, `agent_name`, `server_name`, `package_name`, `package_version`, `ecosystem`, `package_canonical_id` | **none** | persistent | `db/local_analytics.py` |
| `scan_runs` | [Scans, jobs and reports](storage-erd/scans.md) | SQLite | `run_id` | `run_id`, `scan_id`, `tenant_id` | `tenant_id` | persistent | `db/local_analytics.py` |
| `scan_schedules` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite, Snowflake | `schedule_id` | `schedule_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_policy.py`, `api/schedule_store.py` (+1) |
| `scan_snapshot_jobs` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite | `tenant_id`, `job_id` | `tenant_id`, `job_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_scan_snapshot.py`, `api/scan_snapshot_store.py` |
| `scan_snapshot_rows` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite | `tenant_id`, `job_id`, `ordinal` | `tenant_id`, `job_id`, `ordinal`, `canonical_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_scan_snapshot.py`, `api/scan_snapshot_store.py` |
| `schema_version` | [Schema metadata and maintenance](storage-erd/other.md) | SQLite | — | `version` | **none** | persistent | `db/schema.py` |
| `scim_groups` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `tenant_id`, `group_id` | `tenant_id`, `group_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_scim.py`, `api/scim_store.py` |
| `scim_users` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `tenant_id`, `user_id` | `tenant_id`, `user_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_scim.py`, `api/scim_store.py` |
| `side_scan_execution_state` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite | `execution_id` | `execution_id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260929_04_side_scan_lifecycle.py`, `deploy/supabase/postgres/runtime-schema.sql`, `cloud/side_scan_lifecycle_postgres.py` (+1) |
| `skills_scan_run` | [Scans, jobs and reports](storage-erd/scans.md) | Postgres, SQLite | `tenant_id`, `run_id` | `tenant_id`, `run_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/skills_scan_store.py`, `api/storage/registry_schema.py` |
| `sources` | [Connectors, delivery and schedules](storage-erd/connectors.md) | SQLite | `source_id` | `source_id`, `tenant_id` | `tenant_id` | persistent | `api/source_store.py` |
| `strong_members` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `scan_id`, `node_id` | `scan_id`, `node_id` | **none** | scratch | `graph/correlation_workspace.py` |
| `sync_meta` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `source` | `source` | **none** | persistent | `db/schema.py` |
| `teams` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `team_id` | `team_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql` |
| `tenant_graph_retention_overrides` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/tenant_graph_retention_store.py` |
| `tenant_quota_overrides` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/tenant_quota_store.py` |
| `tenant_score_config_overrides` | [Tenancy, identity and access](storage-erd/tenancy.md) | Postgres, SQLite | `tenant_id` | `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/postgres_tenant_score_config.py`, `api/tenant_score_config_store.py` |
| `ticket_links` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `id` | `id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260726_01_ticketing_schema_authority.py`, `deploy/supabase/postgres/runtime-schema.sql`, `ticketing/connection_store.py` (+1) |
| `ticketing_connections` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `id` | `id`, `tenant_id` | `tenant_id` | persistent | `deploy/supabase/postgres/alembic/versions/20260726_01_ticketing_schema_authority.py`, `deploy/supabase/postgres/runtime-schema.sql`, `ticketing/connection_store.py` (+1) |
| `trace_collection_checkpoints` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres | `tenant_id`, `connection_id` | `tenant_id`, `connection_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/trace_collection/schema.py` |
| `trace_collection_receipts` | [Runtime, gateway and traces](storage-erd/runtime.md) | Postgres | `tenant_id`, `connection_id`, `observation_id` | `tenant_id`, `connection_id`, `observation_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/trace_collection/schema.py` |
| `trend_history` | [Findings, triage and VEX](storage-erd/findings.md) | Postgres, SQLite | `id` | `id`, `team_id`, `scan_id` | `team_id` | persistent | `deploy/supabase/postgres/init.sql`, `api/postgres_audit.py`, `baseline.py` |
| `vulnerability_scans` | [Findings, triage and VEX](storage-erd/findings.md) | ClickHouse | `tenant_id`, `scan_id`, `finding_key` | `scan_id`, `tenant_id`, `finding_key` | `tenant_id` | persistent | `deploy/supabase/clickhouse/init.sql`, `cloud/clickhouse.py` |
| `vulns` | [Vulnerability intelligence (local database)](storage-erd/vulndb.md) | SQLite | `id` | `id` | **none** | persistent | `db/schema.py` |
| `webhook_subscriptions` | [Connectors, delivery and schedules](storage-erd/connectors.md) | Postgres, SQLite | `tenant_id`, `subscription_id` | `tenant_id`, `subscription_id` | `tenant_id` | persistent | `deploy/supabase/postgres/runtime-schema.sql`, `api/storage/registry_schema.py`, `api/webhook_store.py` |
| `ws_edges` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `seq` | `tenant_id`, `seq` | `tenant_id` | scratch | `graph/build_workspace.py` |
| `ws_nodes` | [Graph nodes, edges, snapshots and attack paths](storage-erd/graph.md) | SQLite | `seq` | `tenant_id`, `seq` | `tenant_id` | scratch | `graph/build_workspace.py` |

## Schema notes

### Tables without a tenant column

Rows in these tables are not scoped by `tenant_id` / `team_id`. Many are global by design (vulnerability intelligence, schema metadata); the rest are worth a second look.

| Table | Domain | Backends |
|---|---|---|
| `adoption_events` | Schema metadata and maintenance | SQLite |
| `affected` | Vulnerability intelligence (local database) | SQLite |
| `agent_bom_hub_backfills` | Schema metadata and maintenance | Postgres |
| `agent_bom_tenant_binding_keys` | Tenancy, identity and access | Postgres |
| `api_rate_limit_hits` | Tenancy, identity and access | Postgres |
| `api_rate_limits` | Tenancy, identity and access | Postgres |
| `auth_session_attempts` | Tenancy, identity and access | Postgres |
| `bound_references` | Connectors, delivery and schedules | Snowflake |
| `control_plane_schema_versions` | Schema metadata and maintenance | Postgres, SQLite, ClickHouse |
| `cpe_matches` | Vulnerability intelligence (local database) | SQLite |
| `delivery_breaker` | Connectors, delivery and schedules | SQLite |
| `delivery_ledger` | Connectors, delivery and schedules | SQLite |
| `delivery_log` | Connectors, delivery and schedules | SQLite |
| `edge_groups` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `edge_observations` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `epss_scores` | Vulnerability intelligence (local database) | SQLite |
| `graph_retention_state` | Schema metadata and maintenance | SQLite |
| `graph_schema_version` | Schema metadata and maintenance | SQLite |
| `job_overview_identity` | Scans, jobs and reports | SQLite |
| `kev_entries` | Vulnerability intelligence (local database) | SQLite |
| `local_schema_meta` | Schema metadata and maintenance | SQLite |
| `merged_nodes` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `node_groups` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `node_observations` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `osv_cache` | Vulnerability intelligence (local database) | Postgres, SQLite |
| `revoked_session_nonces` | Tenancy, identity and access | Postgres |
| `scan_findings` | Findings, triage and VEX | SQLite |
| `scan_packages` | Inventory and assets | SQLite |
| `schema_version` | Schema metadata and maintenance | SQLite |
| `strong_members` | Graph nodes, edges, snapshots and attack paths | SQLite |
| `sync_meta` | Vulnerability intelligence (local database) | SQLite |
| `vulns` | Vulnerability intelligence (local database) | SQLite |

### Tenant column outside the primary key

These tables carry a tenant column, but their primary key (per backend) does not include it, so two tenants cannot hold the same key value.

| Table | Backend | Primary key | Tenant column |
|---|---|---|---|
| `access_review_campaigns` | SQLite | `campaign_id` | `tenant_id` |
| `access_review_items` | SQLite | `item_id` | `tenant_id` |
| `agent_conditional_access_policies` | Postgres | `policy_id` | `tenant_id` |
| `agent_conditional_access_policies` | SQLite | `policy_id` | `tenant_id` |
| `agent_identities` | Postgres | `identity_id` | `tenant_id` |
| `agent_identities` | SQLite | `identity_id` | `tenant_id` |
| `agent_identity_jit_grants` | Postgres | `grant_id` | `tenant_id` |
| `agent_identity_jit_grants` | SQLite | `grant_id` | `tenant_id` |
| `agents` | Postgres | `agent_id` | `team_id` |
| `api_keys` | Postgres | `key_id` | `team_id` |
| `audit_log` | Postgres | `entry_id` | `team_id` |
| `audit_log` | SQLite | `entry_id` | `tenant_id` |
| `cis_benchmark_checks` | Postgres | `id` | `team_id` |
| `cloud_connections` | Postgres | `id` | `tenant_id` |
| `cloud_connections` | SQLite | `id` | `tenant_id` |
| `control_plane_sources` | Postgres | `source_id` | `tenant_id` |
| `credential_refs` | Postgres | `credential_ref_id` | `tenant_id` |
| `credential_refs` | SQLite | `credential_ref_id` | `tenant_id` |
| `exceptions` | Postgres | `exception_id` | `team_id` |
| `exceptions` | SQLite | `exception_id` | `tenant_id` |
| `exceptions` | Snowflake | `exception_id` | `tenant_id` |
| `export_destinations` | SQLite | `id` | `tenant_id` |
| `export_schedules` | SQLite | `schedule_id` | `tenant_id` |
| `findings` | Postgres | `finding_id` | `team_id` |
| `findings_by_framework` | Snowflake | `finding_id`, `framework_slug` | `tenant_id` |
| `gateway_policies` | Postgres | `policy_id` | `team_id` |
| `gateway_policies` | SQLite | `policy_id` | `tenant_id` |
| `gateway_policies` | Snowflake | `policy_id` | `tenant_id` |
| `governance_audit_log` | Postgres | `seq` | `tenant_id` |
| `governance_audit_log` | SQLite | `seq` | `tenant_id` |
| `hitl_approvals` | SQLite | `item_id` | `tenant_id` |
| `issue_mappings` | SQLite | `mapping_id` | `tenant_id` |
| `job_queue` | Postgres | `job_id` | `team_id` |
| `jobs` | SQLite | `job_id` | `tenant_id` |
| `managed_trial_invitations` | Postgres | `invitation_id` | `tenant_id` |
| `mcp_client_configs` | Postgres | `config_id` | `tenant_id` |
| `mcp_client_configs` | SQLite | `config_id` | `tenant_id` |
| `model_provider_keys` | Postgres | `provider_key_id` | `tenant_id` |
| `model_provider_keys` | SQLite | `provider_key_id` | `tenant_id` |
| `model_virtual_keys` | Postgres | `virtual_key_id` | `tenant_id` |
| `model_virtual_keys` | SQLite | `virtual_key_id` | `tenant_id` |
| `policy_audit_log` | Postgres | `id` | `team_id` |
| `policy_audit_log` | SQLite | `entry_id` | `tenant_id` |
| `policy_audit_log` | Snowflake | `entry_id` | `tenant_id` |
| `policy_results` | Postgres | `result_id` | `team_id` |
| `posture_scores` | ClickHouse | `measured_at`, `agent_name` | `tenant_id` |
| `posture_webhook_outbox` | SQLite | `id` | `tenant_id` |
| `proxy_replay_log` | Postgres | `row_id` | `tenant_id` |
| `proxy_replay_log` | SQLite | `row_id` | `tenant_id` |
| `scan_jobs` | Snowflake | `job_id` | `tenant_id` |
| `scan_runs` | SQLite | `run_id` | `tenant_id` |
| `scan_schedules` | Postgres | `schedule_id` | `tenant_id` |
| `scan_schedules` | SQLite | `schedule_id` | `tenant_id` |
| `scan_schedules` | Snowflake | `schedule_id` | `tenant_id` |
| `side_scan_execution_state` | Postgres | `execution_id` | `tenant_id` |
| `side_scan_execution_state` | SQLite | `execution_id` | `tenant_id` |
| `sources` | SQLite | `source_id` | `tenant_id` |
| `ticket_links` | Postgres | `id` | `tenant_id` |
| `ticket_links` | SQLite | `id` | `tenant_id` |
| `ticketing_connections` | Postgres | `id` | `tenant_id` |
| `ticketing_connections` | SQLite | `id` | `tenant_id` |
| `trend_history` | Postgres | `id` | `team_id` |
| `trend_history` | SQLite | `id` | `tenant_id` |
| `webhook_subscriptions` | SQLite | `subscription_id` | `tenant_id` |
| `ws_edges` | SQLite | `seq` | `tenant_id` |
| `ws_nodes` | SQLite | `seq` | `tenant_id` |

### Postgres and SQLite column differences

Tables defined for both backends whose column sets differ (columns added by `ALTER TABLE … ADD COLUMN` included).

| Table | Postgres only | SQLite only |
|---|---|---|
| `audit_chain_checkpoint` | `updated_at` | — |
| `audit_log` | `team_id` | `tenant_id` |
| `exceptions` | `team_id` | `tenant_id` |
| `fleet_agents` | — | `device_fingerprint` |
| `gateway_policies` | `team_id` | `enabled`, `mode`, `name`, `tenant_id`, `updated_at` |
| `governance_audit_log` | `prev_hash` | — |
| `issue_mappings` | `data` | `created_at`, `external_id`, `external_url`, `status`, `updated_at` |
| `job_overview_revisions` | `generation` | — |
| `kspm_cluster_posture` | `data` | `payload_json` |
| `policy_audit_log` | `id`, `logical_entry_id`, `team_id`, `ts` | `action_taken`, `agent_name`, `policy_id`, `tenant_id`, `timestamp` |
| `skills_scan_run` | `data` | `payload_json` |
| `trend_history` | `team_id` | `tenant_id` |
