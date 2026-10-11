# Security semantics and architecture gates

`agent_bom.core` owns severity labels, histogram/policy ordering and CVSS
validation/scoring. Adapters import those rules rather than reimplementing
thresholds. The kernel cannot import API, scanner, graph, CLI, output or
provider adapters. CVSS 4 scoring loads its scorer only when requested.
Vendor-specific advisory-only fallback policies stay in their adapters;
missing/invalid CVSS is unknown, while a validated zero score is none.

Existing imports through `models.Severity`, `graph.severity` and scanner risk
helpers remain compatibility exports of the same implementations. Package
identity and ecosystem version decisions live in `core/packages.py` and the
bounded `core/versions/` modules. `package_utils` and `version_utils` preserve
existing imports; registry requests and per-scan warning delivery remain in the
outer adapter. Cached range decisions retain dropped-bound evidence so later
scans still report comparison gaps.

Run `python scripts/check_architecture.py` before a PR, or run `make preflight`.
The gate checks semantic ownership and kernel imports and prevents growth in
Python file length, function length and Ruff C901 complexity. New code uses
600 physical lines per file, 80 physical lines per function, and complexity 15.
Existing excess is recorded in `scripts/architecture-baseline.json`; this is
measured debt, not a statement that those units meet the target.

After reducing an existing unit, run
`python scripts/check_architecture.py --write-baseline` and review the reduced
allowance. The command refuses increases. CI also compares allowances against the trusted
base commit, so editing the baseline cannot approve growth. A new or renamed oversized unit has
no inherited exception. The Python gate excludes browser bundles and generated
JSON/schema/TypeScript artifacts, which retain their owning generation checks.
It sets no PR line-count limit.

Finding ledger and current-state reads share `api/storage/finding_reads.py`
and `finding_current_reads.py` across SQLite and Postgres. Explicit tenants are
required. A page's count, rows and reference hydration use one read-only
snapshot, including batched scope filtering. Postgres also applies the
application role's tenant RLS context. SQLite refuses reads on an already
active transaction without rolling back its pending writes.

Ledger/reference writes, current observations and reconciliation use shared
transaction-owned SQL in `api/storage/`. The adapters retain schema bootstrap,
observation-partition validation, commit ownership, post-commit caches and
backend-specific overview aggregates. An ingest failure rolls back its ledger,
references, observation deduplication and current state together; retrying the
same batch remains idempotent. SQLite serializes writes with `BEGIN IMMEDIATE`;
Postgres takes a transaction-scoped advisory lock per tenant before hub row
locks. This prevents concurrent first/current observations from overwriting
one another's scan counts. The lock serializes a tenant's ingestion batches;
throughput under contention requires deployment-specific measurement. Different
tenants use different Postgres lock keys (hash collisions only add contention).

Missing tenant identities fail closed before database access. SQL values stay
bound, and PostgreSQL application-role RLS remains enforced during reads and
writes. No new schema migration is required. Current-state cursors retain the
existing indexed database collation; identical mixed-text order across
differently collated databases is not guaranteed. The SQLite legacy ledger
scan-column backfill uses `batch_id` before `scan_id`, matching ingest/filtering.

The shared SQL keyset helper supports per-column descending flags, including
descending score with ascending tie-breaker. Its text comparisons use binary/C
collation on SQLite/Postgres; matching indexes must use that same collation.
Run `pytest tests/test_storage_sql.py tests/test_findings_sql_read_contract.py
tests/test_findings_sql_backfill.py tests/test_findings_current_sql_contract.py -q` for the contract. The Postgres cases need
a migrated, isolated test database with the non-superuser application and
maintenance URLs; without them those cases are skipped.

Cloud role-assignment projection lives in `graph/cloud_rbac.py`, separate from
the report builder. Azure resource-group graph keys include the complete ARM
scope, normalized for case and trailing slashes; names alone cannot identify a
group across subscriptions. Rescans build these scoped keys; retained historical
snapshots are not rewritten. Authoritative authorization evidence still takes
precedence, and partial evidence does not fall back to legacy role-name edges.

Composer/Packagist recognizes `patch` as a patch-level alias, consistent with
[Composer's version parser](https://github.com/composer/semver/blob/main/src/VersionParser.php).
Native PHP retains its own qualifier ordering. The architecture gate measures
complexity even when a function carries a `noqa` annotation.

Loopback bootstrap credentials live in `api/dev_auth_state.py`. Middleware and
browser key exchange read that process-local state without importing the API
server or its routers. The server preserves the CLI setter/getter exports.
Invalid configured roles fail closed before replacing the active key; clearing
the key disables automatic loopback browser sessions. Host restrictions, tenant
binding and session authorization remain enforced by their existing adapters.

## Finding reads and authentication state

The scan router composes HTTP handlers; finding scope, facets, grouping, merged
pagination, and view filtering live in `api/finding_*.py`. Persisted scan reads
and enrichment live in `api/scan_finding_read.py` and
`api/scan_finding_projection.py`. Export and MCP readers import those services
directly. The router retains compatibility exports, but lower-level helpers
must not import the router. Cursor order, tenant scope, suppression, incomplete
counts, and redaction remain the existing read contracts.

`api/auth_runtime_state.py` owns the applied authentication posture.
`api/auth_posture.py` derives configuration facts; `api/middleware.py` enforces
requests. Derivation preserves the existing anonymous opt-in and role clamp;
missing credentials and tenant scope remain rejected at their existing gates.
Rate-limit persistence lives in `api/rate_limit_store.py`, including the same
Postgres advisory lock and schema-version guard. Clustered initialization
failures must not fall back to an in-process limiter.

Source-defined tools and application entrypoints are projected by
`graph/ast_tool_projection.py`. Framework agents, model links, and observability
edges are projected by `graph/framework_topology_projection.py`, with mutable
projection state scoped to a single build. `graph/builder.py` retains stage
ordering and compatibility exports. Demo graph seeding uses graph services
directly rather than importing an HTTP router.
