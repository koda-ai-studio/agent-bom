# Storage backends and support tiers

agent-bom can persist control-plane state to several engines. They do not
carry the same evidence, so each one has a support tier. The tier is declared
in code (`src/agent_bom/storage/tiers.py`), logged at control-plane startup,
and shown by `agent-bom doctor`.

## Support matrix

| Backend | Tier | Use | Tenant-isolation evidence |
|---|---|---|---|
| PostgreSQL | **supported** | System of record for self-hosted servers, including multi-replica and multi-tenant deployments | Forced row-level security plus application tenant predicates; startup refuses a role that can bypass RLS (`_preflight_postgres_tenant_isolation` in `api/server.py`). Tests: `tests/test_postgres_rls_backstop_parity.py`, `tests/test_rls_superuser_guard.py`, `tests/test_storage_sql.py`, `tests/test_cross_tenant_leakage.py` |
| SQLite | **supported** | Local CLI, single-node and pilot control planes | Application tenant predicates on every read and write; shared SQL with Postgres in `api/storage/` ([architecture boundaries](ARCHITECTURE_BOUNDARIES.md)). Tests: `tests/test_storage_sql.py`, `tests/test_store_tenant_backstop.py`, `tests/test_*_tenant_boundary.py` |
| In-memory | supported for local use only | Default when no database is configured; not durable | Process-local; lost on restart |
| ClickHouse | **analytics sink** | Optional OLAP mirror for traces, proxy audit and scan analytics. Never the system of record for jobs, fleet, policy, audit or graph state | Tenant column on every row and tenant predicate on every scoped query, tested against a mocked client: `tests/test_clickhouse_tenant_isolation.py` |
| Snowflake (control-plane stores) | **experimental** | Selected job, fleet, policy, schedule and exception stores when `SNOWFLAKE_ACCOUNT` is set; used by the [Snowflake Native App](snowflake-native-app/INSTALL.md) | Application tenant predicates plus a row access policy (`agent_bom_tenant_isolation`) attached to tenant tables. The policy admits every row until `agent_bom_tenant_access` role mappings are populated, so the application filter is the effective boundary by default. Both are verified only as rendered SQL against mocked connections (`tests/test_snowflake_stores.py`); there is no live cross-tenant test. **Tenant isolation is not proven.** |
| Neptune (graph) | **experimental** | Graph store when `AGENT_BOM_GRAPH_BACKEND=neptune` and `AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH=1` | Tenant property on vertices and edges, tested against a mocked Gremlin client (`tests/test_neptune_graph_store.py`). **Tenant isolation is not proven.** Generation-owned push persistence is rejected ([architecture](ARCHITECTURE.md)) |

Snowflake warehouse-native discovery and governance routes (Cortex, query
history, account inventory) read from Snowflake as a data source. They are not
covered by this table, which is about where agent-bom stores its own state.

## How the active backend is selected

Precedence mirrors the API startup wiring:

| Component | Order |
|---|---|
| Control plane (jobs, fleet, policy, …) | `SNOWFLAKE_ACCOUNT` → `AGENT_BOM_GRAPH_BACKEND=neptune` (jobs stay in memory) → `AGENT_BOM_POSTGRES_URL` or a Postgres URL in `AGENT_BOM_DB` → SQLite file in `AGENT_BOM_DB` → in-memory |
| Graph | `AGENT_BOM_GRAPH_BACKEND=neptune` → Postgres → SQLite |
| Analytics | `AGENT_BOM_ANALYTICS_BACKEND=clickhouse`, or `AGENT_BOM_CLICKHOUSE_URL` with the backend unset or `auto` |

## Startup behavior

- **Supported backends and the ClickHouse sink:** no storage-tier log line.
- **Experimental backend (default, advisory):** the API logs one `WARNING`
  that names each experimental backend and component, its tier, and this page.
  The log record carries a `context` object
  (`event=storage_tier_experimental`) for JSON log pipelines. When the
  deployment looks multi-tenant (`AGENT_BOM_REQUIRE_TENANT_BOUNDARY=1`,
  `AGENT_BOM_CONTROL_PLANE_REPLICAS` greater than 1, or
  `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` set), the warning states that tenant
  isolation for that backend is not proven. Startup continues, so existing
  deployments, including the Snowflake Native App, keep working.
- **Strict mode (opt-in):** set `AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1` and the
  API refuses to start when an experimental backend is selected. An invalid
  value for this variable also refuses startup instead of being ignored.

Check the effective tiers without starting the API:

```bash
agent-bom doctor --offline
agent-bom --agent-mode doctor --offline   # JSON; see data.platform
```

Experimental rows show as warnings and count toward the doctor warning total.

## Migrating to PostgreSQL

1. Provision PostgreSQL and run the control-plane migrations with the
   maintenance role. Configure the restricted application role in
   `AGENT_BOM_POSTGRES_URL` ([enterprise deployment](DEPLOY_PLATFORM.md)).
2. **From SQLite:** import evidence registries with the operator-controlled,
   dry-run-first import in
   [operations/sqlite-registry-import.md](operations/sqlite-registry-import.md).
3. **From Snowflake or Neptune:** there is no automated migration. Unset
   `SNOWFLAKE_ACCOUNT` (control-plane stores) or `AGENT_BOM_GRAPH_BACKEND`
   (graph) for the API process, then re-run scans and fleet sync so jobs,
   inventory and graph snapshots are rebuilt in PostgreSQL. Export any
   Snowflake-held policy or exception records you need to keep before switching.
4. Set `AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1` so a later configuration change
   cannot silently reintroduce an experimental backend.
5. Run `agent-bom doctor` and confirm every storage row reads `supported` or
   `analytics sink`.

ClickHouse can stay configured alongside PostgreSQL as the analytics sink.

See also: [backend parity by route](../site-docs/deployment/backend-parity.md).

## Postgres sizing for typical estates

The numbers below are derived from the synthetic graph cardinalities published
in [`docs/perf/ingest-throughput.md`](perf/ingest-throughput.md). They are
floor estimates for the `graph_nodes` and `graph_edges` tables in
`src/agent_bom/api/postgres_store.py` only — multiply by retention factor and
add the audit log (`audit_events`, append-only) when sizing total disk.

| Estate size | Nodes | Edges | Graph rows | RDS storage floor (graph) | Recommended `db.t4g.medium`+ profile |
|---|---:|---:|---:|---|---|
| 1k agents  |  5,201 |  5,200 |  10,401 |  ~24 MiB | 2 vCPU / 4 GiB / 20 GiB gp3 |
| 5k agents  | 26,001 | 26,000 |  52,001 | ~120 MiB | 2 vCPU / 4 GiB / 50 GiB gp3 |
| 10k agents | 52,001 | 52,000 | 104,001 | ~240 MiB | 4 vCPU / 8 GiB / 100 GiB gp3 |

These rows are **disk/floor estimates from synthetic ingest cardinalities**, not
a proven graph-API read latency ceiling. The checked-in query/API measured
ceiling remains ~10,479 nodes / 11,242 edges — see
[`docs/perf/graph-api-postgres-benchmark.md`](perf/graph-api-postgres-benchmark.md).
Do not cite the 52k-node sizing row as measured read performance.

Verify the actual disk used by the graph tables in your deployment with:

```sql
SELECT relname,
       pg_size_pretty(pg_total_relation_size(C.oid)) AS total_size,
       pg_size_pretty(pg_relation_size(C.oid))       AS table_size,
       pg_size_pretty(pg_indexes_size(C.oid))        AS index_size
FROM   pg_class C
LEFT   JOIN pg_namespace N ON (N.oid = C.relnamespace)
WHERE  relkind = 'r' AND nspname = 'public'
   AND relname IN ('graph_nodes', 'graph_edges', 'audit_events',
                   'scan_jobs', 'compliance_evidence')
ORDER  BY pg_total_relation_size(C.oid) DESC;
```

Persistence throughput against these row counts is tracked in #1806; the
weekly `perf-scale-evidence.yml` workflow regenerates the in-process scale
floor on the lightweight 1k-estate set.

For horizontally scaled SCIM, shared identity storage is also mandatory. Set `AGENT_BOM_POSTGRES_URL` for EKS or any multi-replica control plane, and keep `AGENT_BOM_REQUIRE_SHARED_SCIM_STORE=1` enabled in production values. SQLite is acceptable only for a single-node pilot.

## Durable-by-default lifecycle state

The agent-identity store (issued tokens, rotation/revocation state), JIT grants,
conditional-access policies, and the runtime session/observation timeline are
**durable by default** — a control plane must not drop issued tokens, grants, or
sessions on a single-replica restart. Backend selection, with no extra wiring:

| Configuration | Backend | Durability |
|---|---|---|
| `AGENT_BOM_POSTGRES_URL` set | PostgreSQL with tenant `FORCE ROW LEVEL SECURITY` | Multi-replica — state is consistent across every control-plane replica |
| `AGENT_BOM_DB` set to a file path | SQLite at that path | Single-node durable (survives restart) |
| _nothing set_ (default) | SQLite at `${AGENT_BOM_STATE_DIR:-~/.agent-bom}/control-plane.db` | Single-node durable (survives restart) |
| `AGENT_BOM_EPHEMERAL_STORE=1` | In-memory | **Not durable** — state is lost on restart |

`AGENT_BOM_DB` accepts a SQLite filesystem path. A database URL in that
variable stops API startup before stores initialize; diagnostics omit the URL
and credentials. Configure PostgreSQL with `AGENT_BOM_POSTGRES_URL`. This
validation does not migrate existing files or establish PostgreSQL parity for
every store. Preserve any SQLite files created by earlier configurations for
explicit inspection and import; changing configuration does not move their data.

Delegation tokens are stored only as SHA-256 hashes at rest, sessions stay signed with
expiry and revocation, and tenant isolation holds across all three tiers — the
durable default does not weaken any of these. Use `AGENT_BOM_EPHEMERAL_STORE=1`
only for throwaway CI jobs or tests that explicitly want in-memory state; never
in production. For any multi-replica deployment set `AGENT_BOM_POSTGRES_URL` so
identity, JIT, and session state stay consistent across replicas instead of
diverging on node-local SQLite.

Production deployments must keep cryptographic keys separated by purpose:

- `AGENT_BOM_AUDIT_HMAC_KEY` signs the tamper-evident audit chain and audit exports.
- `AGENT_BOM_RATE_LIMIT_KEY` fingerprints API keys for rate-limit buckets.
- `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` signs httpOnly browser session cookies.
- `AGENT_BOM_DELEGATION_SIGNING_KEY` signs scoped agent-to-agent delegation tokens; set it (never reuse another key) so delegated handoffs verify consistently across replicas and survive restarts. When unset, a per-process ephemeral key is used and tokens become invalid after restart.
- `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` attests trusted reverse-proxy identity headers and must contain at least 32 bytes of secret material.

Do not reuse the API key or audit HMAC key as a rate-limit, browser-session, or proxy-attestation secret. Set `AGENT_BOM_TRUST_PROXY_AUTH_ISSUER` when the upstream proxy can inject a stable issuer identifier; the API will then reject trusted-proxy requests from any other issuer.

## Side-scan lifecycle storage

Before upgrading a Postgres control plane, run the deployment's Alembic upgrade
with its migration credentials. Revision `20260929_04` provisions side-scan
execution and cleanup state, indexes, tenant RLS and application DML grants.
The runtime application role only checks the schema version; missing migrations
fail startup instead of requesting schema-creation privileges. Rollback preserves
execution and cleanup evidence.

Run an explicitly authorized side-scan to produce its lifecycle record, then
inspect completion and cleanup status before retrying failed work. The storage
contract does not establish live AWS, Azure or GCP execution proof.

## Buffered analytics

For ClickHouse-backed analytics, make the backend explicit instead of relying on ambient environment alone:

```bash
agent-bom api \
  --api-key "$AGENT_BOM_API_KEY" \
  --analytics-backend clickhouse \
  --clickhouse-url "http://clickhouse.internal:8123" \
  --analytics-max-queue 10000
```

Server mode enables buffered ClickHouse writes by default so scan and runtime paths do not block on OLAP round-trips. The queue is bounded (`--analytics-max-queue`, default 10,000 entries): when it fills, the oldest queued evidence is dropped so producers remain non-blocking and recent evidence is preserved. Drops are rate-limited in logs and counted in health output. Authenticated `GET /v1/system/health` reports the active analytics contract (`backend`, `enabled`, `buffered`, `flush_interval_seconds`, `max_batch`, `queue_capacity`, `queue_depth`, `dropped_count`) alongside tracing so operators can confirm both observability and analytics posture from one probe. The ClickHouse analytics path stores scan metadata, vulnerability rows, runtime events, posture snapshots, fleet trust/lifecycle snapshots, compliance control measurements, and audit-event trends so the fleet backend matches the operator story more closely.

## Tenant-scoped job key migration

The jobs schema upgrade `20260928_01` requires a maintenance window. Drain scan
submissions and all distributed workers, stop old API replicas, and take a database
backup before upgrading. This replaces the global job key with `(team_id, job_id)`
and all five dependent references, including the dispatch queue's
`(tenant_id, job_id)` key. Existing job JSON, child IDs, queue claim tokens and lease
expiries are retained. Inconsistent child ownership aborts the entire migration;
review the affected records before retrying. Do not rewrite tenant ownership to
force an upgrade through.

Run `alembic -c deploy/supabase/postgres/alembic.ini upgrade head` using the
configured migration identity, or allow the Helm migration hook below to run after
draining the old replicas. Verify `control_plane_schema_versions` reports
`scan_jobs` version `2`, then start the new replicas and workers. Their lease
heartbeats and completion calls include both tenant and claim owner. Repeating
`upgrade head` is supported. Old PostgreSQL writers using `ON CONFLICT (job_id)`
are incompatible with the new key; mixed-version workers are unsupported. Rollback
requires restoring the pre-upgrade backup and matching application version while
writers remain stopped; the migration has no destructive downgrade.

SQLite performs the equivalent transactional key upgrade at startup and retains
its deployed `jobs.tenant_id` and JSON-text columns. Stop old processes and back up
the database before starting the new version. PostgreSQL retains
`scan_jobs.team_id` and JSONB; shared job SQL maps those physical names. This
contract applies to SQLite, PostgreSQL and the in-memory job store. The retained
Snowflake adapter has not been qualified for tenant-colliding job IDs or PostgreSQL
dispatch leases; this upgrade makes no such claim for it.

## Compressed scan-job results

SQLite and PostgreSQL store a job's `result` and `result_document` zstd-compressed
when their JSON is 4 KiB or larger. The row stays valid JSON / JSONB: the value is
replaced by an envelope

```json
{"__abom_codec": {"codec": "zstd", "encoding": "base64", "v": 1, "raw_bytes": 721334},
 "scan_sources": ["..."], "findings_count": 51, "vulnerabilities_count": 0,
 "data": "<base64 zstd>"}
```

Every reader decodes it transparently (`agent_bom.api.job_payload_codec`), and
rows written before this release, small results and pending jobs remain plain JSON
and read unchanged, so no data migration runs. Top-level job keys such as
`source_id` and `request` stay uncompressed, so `data->>'source_id'` search and the
summary columns are unaffected. SQL that reads inside a stored result may use only
the envelope keys `scan_sources`, `findings_count` and `vulnerabilities_count` (or
the plain arrays on uncompressed rows); `tests/test_job_result_codec.py` fails if a
query reaches any other key. An unknown codec version fails the read rather than
returning an envelope as data. Measured sizes are in
[`docs/perf/report-volume.md`](perf/report-volume.md).

Stored job result fields are limited to 256 MiB of decoded JSON; individual
compliance-hub finding payloads are limited to 16 MiB. New writes enforce these
limits too. Compressed reads bound the encoded input and decompression window
(16 MiB), require one complete zstd frame without trailing data, and check a
job result's decoded size against its header. Corrupt or oversized compressed
evidence fails the read; it is never replaced with an empty, apparently clean
finding. Preserve the original row when investigating a failed read.

Releases before this one read a compressed result as the envelope itself. During
a rolling upgrade, or before a downgrade, set `AGENT_BOM_JOB_RESULT_CODEC=none` on
every writer so new rows stay readable by the older version; rows already
compressed are only readable by this release or later, so a downgrade past it
needs the pre-upgrade backup. The retained Snowflake adapter writes plain JSON and
reads both forms.

Postgres schema migrations for the control plane run automatically on Helm
`pre-install` / `pre-upgrade` when `controlPlane.migrations.enabled` is true
(the default). Operators do not run Alembic manually before routine chart
upgrades; see [`DEPLOY_PLATFORM.md`](DEPLOY_PLATFORM.md) and
[`site-docs/deployment/control-plane-helm.md`](../site-docs/deployment/control-plane-helm.md).
