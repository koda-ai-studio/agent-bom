# Compliance, audit and evidence

> Generated from the code by `scripts/generate_graph_data_model.py`. Do not edit by hand: re-run the
> generator and commit the result. CI runs it with `--check` and fails on drift.

Storage tables in this domain. Back to the [storage ERD](../storage-erd.md).

10 tables.

Tables from other domains drawn for their relations: `gateway_policies`, `scan_jobs`, `teams`.

```mermaid
erDiagram
  attestation_replay {
    text tenant_id PK
    text evidence_id PK
    text nonce PK
  }
  audit_chain_checkpoint {
    text tenant_id PK
  }
  audit_events {
    string entry_id PK
    string tenant_id PK
  }
  audit_log {
    text entry_id PK
    text team_id
  }
  cis_benchmark_checks {
    bigserial id PK
    string scan_id FK
    text team_id FK
  }
  compliance_controls {
    string scan_id PK
    string tenant_id PK
    string control_key PK
  }
  evaluation_runs {
    text tenant_id PK
    text evaluation_id PK
  }
  governance_audit_log {
    bigserial seq PK
    text tenant_id
  }
  hub_framework_refs {
    text tenant_id PK
    text framework_ref PK
  }
  policy_results {
    text result_id PK
    text scan_run_id FK
    text team_id FK
    text policy_id FK
  }
  gateway_policies {
    varchar policy_id PK
    text team_id
  }
  scan_jobs {
    varchar job_id PK
    text team_id PK, FK
    text schedule_id
  }
  teams {
    text team_id PK
  }
  gateway_policies ||--o{ policy_results : "policy_id"
  scan_jobs ||--o{ cis_benchmark_checks : "scan_id"
  scan_jobs ||--o{ policy_results : "scan_run_id"
  teams ||--o{ cis_benchmark_checks : "team_id"
  teams ||--o{ policy_results : "team_id"
```

## Relations

| Parent | Child | Column | Kind |
|---|---|---|---|
| `gateway_policies` | `policy_results` | `policy_id` | declared FK |
| `scan_jobs` | `cis_benchmark_checks` | `scan_id → scan_jobs.job_id` | declared FK |
| `scan_jobs` | `policy_results` | `scan_run_id → scan_jobs.job_id` | declared FK |
| `teams` | `cis_benchmark_checks` | `team_id` | declared FK |
| `teams` | `policy_results` | `team_id` | declared FK |

## Shared key columns without an owning table

Same column name in several tables here, but no table owns it, so no join is drawn.

| Column | Tables |
|---|---|
| `entry_id` | `audit_events`, `audit_log` |

## Tables

| Table | Backends | Columns | Partitioned |
|---|---|---|---|
| `attestation_replay` | SQLite | 4 |  |
| `audit_chain_checkpoint` | Postgres, SQLite | 4 |  |
| `audit_events` | ClickHouse | 10 | yes |
| `audit_log` | Postgres, SQLite | 10 |  |
| `cis_benchmark_checks` | Postgres, ClickHouse | 22 | yes |
| `compliance_controls` | ClickHouse | 11 | yes |
| `evaluation_runs` | Postgres, SQLite | 5 |  |
| `governance_audit_log` | Postgres, SQLite | 8 |  |
| `hub_framework_refs` | Postgres, SQLite | 4 |  |
| `policy_results` | Postgres | 10 |  |
