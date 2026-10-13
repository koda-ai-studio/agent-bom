# Trace collection recovery and load qualification

Use a disposable database and a fresh output directory for every run. This
qualification sends authenticated requests through the in-process ASGI test
transport and serves synthetic Langfuse pages through `httpx.MockTransport`.
It exercises the real adapter, authorization, audit, SQL transactions, and
checkpoint implementation. One shared TestClient lifespan serves all requests
on one event loop and applies `AGENT_BOM_WORKER_THREAD_LIMIT`, matching the API's
worker admission boundary. Fixture stores are provisioned before that lifespan;
external startup provisioning is excluded. It does not measure a deployed HTTP server, a live
provider account, network latency, or production capacity.

## First run: SQLite

```bash
uv sync --frozen --extra dev --extra api
# Use a test-only persistent key so fixture audit signatures survive restart.
export AGENT_BOM_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export AGENT_BOM_WORKER_THREAD_LIMIT=2
uv run python -m scripts.run_trace_collection_qualification \
  --output /tmp/trace-qualification-sqlite-001
```

The output contains `attempts.jsonl`, `receipt.json`, and SQLite runtime/audit
databases. The receipt records the source commit, whether the checkout was
dirty, configuration, serving-loop and worker-thread limits, Python/platform, all-attempt latency percentiles, process
peak RSS, provider calls, and exact reconciliation outcome. Failed requests
remain in latency/error totals. Warmup is recorded separately and excluded from
the baseline. An existing output directory is rejected, not overwritten.

Default load is three collection connections in a noisy tenant and one in a
light tenant: ten pages of 100 observations per connection, with concurrent
light-tenant status reads. Provider source IDs deliberately repeat across
connections and tenants. Reconciliation requires the exact expected observation
IDs, page counts, insertion counts, and completed checkpoints for both tenants.
No failed request or missing work can yield a passing receipt. Queue-overload
responses also fail the run; this harness does not retry or hide them.

Earlier versions created a new TestClient event loop for each request, bypassing
the configured shared worker budget. Preserve those receipts, but compare code
changes using the same harness and limits on both revisions. Do not attribute a
change in transport or baseline to a production speedup.

The predeclared local thresholds are light-tenant p95 below 5 seconds and at
most 4 times its warm baseline (using a 1 ms denominator floor). Set
`--p95-limit-ms` and `--slowdown-limit` before a run when qualifying a different
environment. Preserve failed receipts when changing a budget; do not turn a
failed result into a passing one by dropping slow requests. These thresholds
are qualification inputs, not a published product SLO. Shared-runner latency is
not a correctness gate in CI.

## PostgreSQL

Apply the repository's Alembic migrations to a disposable database and configure
its separate application and maintenance logins using the
[PostgreSQL deployment guide](../../site-docs/deployment/control-plane-helm.md). The application role must be
`NOSUPERUSER NOBYPASSRLS`; the maintenance login is needed by audit startup and
must use the existing maintenance marker role. Never substitute the database
administrator for either runtime login.

```bash
uv sync --frozen --extra dev --extra api --extra postgres
export AGENT_BOM_POSTGRES_URL='postgresql://agent_bom_app:TEST_PASSWORD@127.0.0.1:5432/agentbom_test'
export AGENT_BOM_POSTGRES_MAINTENANCE_URL='postgresql://agent_bom_maintenance:TEST_PASSWORD@127.0.0.1:5432/agentbom_test'
uv run python -m scripts.run_trace_collection_qualification \
  --backend postgres --output /tmp/trace-qualification-postgres-001
uv run pytest -q tests/test_trace_collection_postgres.py \
  tests/test_trace_collection_recovery.py tests/test_trace_collection_qualification.py
```

The recovery suite kills a child process before checkpoint commit and after a
successful commit whose acknowledgment is lost. It also terminates its own
PostgreSQL connection mid-transaction and races eight claimants for one lease.
The invariants are page/checkpoint atomicity, one lease owner, recovery after
expiry, and no duplicated observation/session counts. PostgreSQL cases skip
without their database environment; CI runs them in its migrated storage job.
These are correctness checks, separate from machine-dependent load receipts.

## Next step: deployment and provider qualification

### Mixed runtime writes over HTTP

The runtime workload is separate from trace collection. It runs 40 authenticated
write requests of 50 synthetic events and 480 collection-status reads at
concurrency 10, after 30 baseline reads. The load generator and loopback HTTP
API replicas run in separate processes, using real SQL and middleware. Each
request uses a fresh client and connection but shares a preloaded certificate
context, so repeated trust-store parsing does not dominate plaintext HTTP load.
The attempts record client setup and HTTP response time separately; the gate
still uses total request time. Collection
status uses a synthetic configured connection; no provider request is made.
Application lifespan provisioning, ingress and live provider access are outside
this command.

```bash
AGENT_BOM_STATE_DIR=/tmp/runtime-capacity-state-001 \
  uv run python -m scripts.run_runtime_capacity_qualification \
  --output /tmp/runtime-capacity-001
```

Use `--backend postgres --replicas 2` with the disposable application and
maintenance roles above for two PostgreSQL-backed API processes, or `--replicas 4`
for a four-process profile. Each runtime store pool has a minimum of one and
maximum of two connections. Set the shared pool and worker limits explicitly
before comparing runs; the command applies the ordinary API worker cap and
records all three limits in its receipt:

```bash
export AGENT_BOM_POSTGRES_POOL_MIN_SIZE=1
export AGENT_BOM_POSTGRES_POOL_MAX_SIZE=2
export AGENT_BOM_WORKER_THREAD_LIMIT=2
AGENT_BOM_STATE_DIR=/tmp/runtime-capacity-state-004 \
  uv run python -m scripts.run_runtime_capacity_qualification \
  --backend postgres --replicas 4 --output /tmp/runtime-capacity-004
```

The API process count corresponds to `controlPlane.api.replicas` for a Helm
configuration running one API process per pod. A local profile is an input to
staging qualification, not a reason to change a production replica count without
repeating the workload there. Increasing only the database pool is a different
profile and requires its own receipt.

The fixed local gate requires zero failed requests, exactly
500 retained observations per writer tenant with matching session rollups, no
reader-tenant observations, complete verified audit chains, read p95 at most 5 seconds and slowdown at most 4×.
Inspect `attempts.jsonl` and `receipt.json`; retain failed runs. Run on an idle
host without overlapping test/build jobs. A noisy baseline can make the ratio
appear better, so record host contention and repeat from a clean pinned commit
before using a pass as qualification. A local pass does not supersede a failed
deployment measurement.

### Execution and enterprise fixture coverage

Run the [qualified fixture suite](../RUNTIME_FIXTURE_QUALIFICATION.md) to check
execution/effect distinctions, tenant boundaries and recorded access changes.

Inspect `passed`, reconciliation, errors, and all-attempt latency in the receipt.
A process error or missing receipt is a failed run. Keep the JSONL attempts even
when setup or reconciliation fails. Keep local receipts outside the public tree;
they can describe a private machine or deployment.

Before adoption, repeat against a customer-controlled staging deployment using
its ordinary authentication boundary and the managed connection workflow in
[Trace connections](../TRACE_CONNECTIONS.md). Verify a known provider observation,
its preserved trace/span IDs in the explorer, a saved checkpoint after restart,
and provider-side rate-limit behavior. Record the exact provider API/version and
collection window. This harness does not establish live-provider compatibility,
completeness outside the overlap window, multi-replica HTTP capacity, or a
production availability SLO.
