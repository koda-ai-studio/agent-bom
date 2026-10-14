# Runtime, gateway and traces

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Storage tables in this domain. Back to the [storage ERD](../storage-erd.md).

17 tables.

Tables from other domains drawn for their relations: `policy_results`.

```mermaid
erDiagram
  gateway_activity_events {
    text tenant_id PK
    text event_id PK
  }
  gateway_activity_sequences {
    text tenant_id PK
  }
  gateway_activity_tombstones {
    text tenant_id PK
    text event_id PK
  }
  gateway_policies {
    varchar policy_id PK
    text team_id
  }
  llm_cost_budgets {
    text tenant_id PK
    text agent PK
    text cost_center PK
    text owner PK
    text workflow PK
  }
  llm_costs {
    text tenant_id PK
    text call_id PK
    text session_id
  }
  policy_audit_log {
    serial id PK
    text team_id
  }
  posture_scores {
    datetime measured_at PK
    string tenant_id
    string agent_name PK
  }
  proxy_replay_log {
    text row_id PK
    text tenant_id
  }
  runtime_events {
    string event_id PK
    string tenant_id PK
  }
  runtime_observation_revisions {
    text tenant_id PK
    text observation_id PK
    integer revision PK
  }
  runtime_observations {
    text tenant_id PK
    text observation_id PK
    text session_id
  }
  runtime_sessions {
    text tenant_id PK
    text session_id PK
  }
  runtime_trace_imports {
    text tenant_id PK
    text import_id PK
  }
  runtime_workload_evidence {
    text tenant_id PK
    text provider PK
    text account_id PK
    text workload_ref PK
    text dedup_key PK
  }
  trace_collection_checkpoints {
    text tenant_id PK
    text connection_id PK
  }
  trace_collection_receipts {
    text tenant_id PK
    text connection_id PK
    text observation_id PK
  }
  policy_results {
    text result_id PK
    text scan_run_id FK
    text team_id FK
    text policy_id FK
  }
  gateway_policies ||..o{ policy_audit_log : "logical policy_id"
  gateway_policies ||--o{ policy_results : "policy_id"
  runtime_observations ||..o{ runtime_observation_revisions : "logical observation_id"
  runtime_observations ||..o{ trace_collection_receipts : "logical observation_id"
  runtime_sessions ||..o{ llm_costs : "logical session_id"
  runtime_sessions ||..o{ runtime_observations : "logical session_id"
  trace_collection_checkpoints ||..o{ trace_collection_receipts : "logical connection_id"
```

## Relations

| Parent | Child | Column | Kind |
|---|---|---|---|
| `gateway_policies` | `policy_audit_log` | `policy_id` | logical |
| `gateway_policies` | `policy_results` | `policy_id` | declared FK |
| `runtime_observations` | `runtime_observation_revisions` | `observation_id` | logical |
| `runtime_observations` | `trace_collection_receipts` | `observation_id` | logical |
| `runtime_sessions` | `llm_costs` | `session_id` | logical |
| `runtime_sessions` | `runtime_observations` | `session_id` | logical |
| `trace_collection_checkpoints` | `trace_collection_receipts` | `connection_id` | logical |

## Shared key columns without an owning table

Same column name in several tables here, but no table owns it, so no join is drawn.

| Column | Tables |
|---|---|
| `event_id` | `gateway_activity_events`, `gateway_activity_tombstones`, `runtime_events` |
| `source_id` | `runtime_events`, `runtime_workload_evidence` |

## Tables

| Table | Backends | Columns | Partitioned | Lifetime |
|---|---|---|---|---|
| `gateway_activity_events` | Postgres, SQLite | 7 |  | persistent |
| `gateway_activity_sequences` | Postgres, SQLite | 2 |  | persistent |
| `gateway_activity_tombstones` | Postgres, SQLite | 4 |  | persistent |
| `gateway_policies` | Postgres, SQLite, Snowflake | 8 |  | persistent |
| `llm_cost_budgets` | Postgres, SQLite | 8 |  | persistent |
| `llm_costs` | Postgres, SQLite | 13 |  | persistent |
| `policy_audit_log` | Postgres, SQLite, Snowflake | 14 |  | persistent |
| `posture_scores` | ClickHouse | 10 | yes | persistent |
| `proxy_replay_log` | Postgres, SQLite | 5 |  | persistent |
| `runtime_events` | ClickHouse | 16 | yes | persistent |
| `runtime_observation_revisions` | Postgres | 5 |  | persistent |
| `runtime_observations` | Postgres, SQLite | 5 |  | persistent |
| `runtime_sessions` | Postgres, SQLite | 4 |  | persistent |
| `runtime_trace_imports` | Postgres | 4 |  | persistent |
| `runtime_workload_evidence` | Postgres, SQLite | 12 |  | persistent |
| `trace_collection_checkpoints` | Postgres | 3 |  | persistent |
| `trace_collection_receipts` | Postgres | 5 |  | persistent |
