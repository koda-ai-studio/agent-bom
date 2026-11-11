# Performance Benchmarks and Target SLOs

Measured numbers for the agent-bom scanner hot paths that matter at
pilot scale. Run on a MacBook Pro (M-series, 2026) with Python 3.13.
Your infra will vary — treat these as the reference curve, not the
contract. The target SLOs below are the operator envelope we use for
pilot and production readiness decisions.

Run them yourself:

```bash
pip install 'agent-bom[dev]'
pytest tests/benchmarks/ --benchmark-only --benchmark-columns=min,mean,max,stddev,ops
AGENT_BOM_BENCH_FULL=1 pytest tests/benchmarks/ --benchmark-only -k 50k  # heaviest
```

For control-plane and graph API baselines against a running deployment:

```bash
k6 run deploy/loadtest/k6-control-plane-api.js
k6 run deploy/loadtest/k6-graph-api.js
k6 run deploy/loadtest/k6-proxy-audit.js
```

For a bounded high-degree storage workload, use a new task-owned database and
receipt path on every run:

```bash
python scripts/qualify_graph_store.py --sqlite /tmp/graph-run.db --executor processes --seconds 30 --nodes 10000 --output /tmp/graph-run.json
python scripts/qualify_graph_store.py --sqlite /tmp/graph-run.db --verify-checkpoint /tmp/graph-run.json --output /tmp/graph-reopen.json
```

The fixture places every relationship on one root and runs independent readers
and writers for two tenants. Reader receipts include p50/p95 latency and compact
JSON payload bytes for the first 512 completed page pairs, with the sample count
and limit explicit. Latency excludes payload serialization; sizes describe store
page documents, not HTTP wire bytes. Generation restarts are counted separately
from completed reads. A run with no completed pairs has no read latency estimate.
Reopening verifies stored revisions, counts and content digests. This is synthetic
local evidence, not a production capacity, crash recovery, PostgreSQL failover,
or cloud qualification claim. Keep the database and receipts outside the repo.

For end-to-end CLI scan cost (wall, CPU, peak RSS, JSON size) and
`agent-bom --help` cold start, using a synthetic npm lockfile built from
package names in the local vulnerability DB (run `agent-bom db update` first):

```bash
python scripts/bench/scan_throughput_bench.py --sizes 200,1000,2000 --runs 3 --cold-start-runs 5
```

CPU time is the primary metric; the script records the load average with
each run because wall time is unreliable on a shared host.

Release-quality scale evidence for 1k / 5k / 10k estate claims is tracked
under [`docs/perf/`](perf/). Those pages carry the exact commands,
environment fields, raw-result locations, and gaps used for enterprise
procurement evidence. Validate the scaffold with:

```bash
python scripts/check_scale_evidence.py
```

---

## Current-estate agent counts

`GET /v1/posture/counts` uses a scalar SQLite/Postgres query over the current
source snapshots. It counts stored node IDs without decoding node attributes,
loading edges, or generating and persisting derived paths. Duplicate IDs follow
the same ordered-source merge semantics as the full graph; partial and missing
snapshots retain the same prior evidence.

The response keeps the current-estate identifier derived from the selected
source revisions. Opening the full graph materializes that view when needed.
Changing evidence triggers bounded retries; unresolved churn returns an unknown
agent count, and a subsequent graph read in the same request refuses to mix
revisions. Existing request-pinned graphs and backends without the scalar query
retain their node-page read path. No extra index or retained count table is added.

Run the scope, invalidation and API parity regressions with:

```bash
pytest tests/api/test_current_graph_counts.py tests/api/test_api_agent_population.py
```

The real Postgres count/RLS regression is included in the existing migrated
storage-contract CI job (`tests/test_current_graph_assembly_postgres.py`). These
checks establish count parity, not a production capacity or whole-platform cost
claim. Use the control-plane load test above to measure your deployment.

## Scanner hot paths

### Blast-radius tag indexing — `_index_blast_radii_by_tag`

The O(n × k) pass that feeds every compliance bundle. Measured across
1k / 10k / 50k blast-radius findings each tagged under all 15
compliance frameworks (≈15 tag fields per finding).

| Inventory size | Mean | StdDev | Throughput |
|---:|---:|---:|---:|
| 1,000 findings | **0.78 ms** | 0.08 ms | 1,280 ops/sec |
| 10,000 findings | **8.35 ms** | 0.42 ms | 120 ops/sec |
| 50,000 findings | **44.3 ms** | 0.81 ms | 22 ops/sec |

**Scaling:** linear — 50x input → 56x latency. No superlinear blow-up.

**Implication for pilot teams:** a 50k-package agent fleet rebuilds the
tag index in under 50 ms. You can re-index on every evidence-bundle
export without caching; caching becomes interesting only above ~200k
findings.

### OSV fallback accounting — `skipped_non_osv_ecosystems`

The scanner tracks packages that deliberately skip the OSV network path
because their ecosystem is not OSV-backed (for example MCP registry
entries and other non-package inventory rows). This counter is not a
false-negative bucket; it is the expected accounting for inventory
surfaces that never belonged in the OSV query set.

**Implication for operators:** rising `skipped_non_osv_ecosystems`
counts usually mean your inventory mix includes more registry or
non-package metadata, not that vulnerability coverage regressed.

### Compliance bundle signature — HMAC-SHA256 over canonical JSON

The signing path behind `/v1/compliance/{framework}/report`. Measured
with representative evidence payloads of 100 / 1,000 / 10,000 controls
each carrying a variable number of evidence entries.

| Controls per bundle | Mean | Throughput |
|---:|---:|---:|
| 100 controls | **0.20 ms** | 4,930 ops/sec |
| 1,000 controls | **1.93 ms** | 519 ops/sec |
| 10,000 controls | **19.4 ms** | 51 ops/sec |

**Scaling:** linear in canonical-JSON size — serialisation dominates
over HMAC-SHA256 itself.

**Implication:** a realistic 15-framework report (≈220 controls total
across frameworks, up to ~10 evidence entries each) signs in **under 5
ms** end-to-end. Ed25519 adds ~0.2 ms on top.

### Unified graph build — `build_unified_graph_from_report`

The hot path behind `/v1/scan/{job_id}/context-graph` and the UI
mesh / attack-path views. Walks a scan report JSON into a
`UnifiedGraph` of agents + servers + packages + tools + credentials +
blast-radius edges.

Measured on a MacBook Pro (M-series, 2026), Python 3.13. Source:
`tests/benchmarks/test_graph_hot_paths.py`.

| Scale | Agents × Servers × Packages | Mean build time | Throughput |
|---|---|---:|---:|
| Small team | 20 × 2 × 5 = 200 pkgs | **0.71 ms** | ~1,415 ops/sec |
| Departmental | 100 × 2 × 5 = 1,000 pkgs | **3.78 ms** | ~265 ops/sec |
| Company-wide | 500 × 2 × 10 = 10,000 pkgs | **42.0 ms** | ~24 ops/sec |
| Enterprise (50k variant) | 1,000 × 5 × 10 = 50,000 pkgs | **50.5 ms** | ~20 ops/sec |

**Scaling:** effectively linear in package count up to 10k (builder is
O(agents + servers + packages + edges)); the 50k jump is actually
cheaper per-package than 10k because the synthetic fixture reuses
package keys across servers, so dedup amortises cost.

**Deployment implications:**

- These are in-process graph-builder timings for the stated synthetic fixtures.
  Package counts can collapse into fewer deduplicated graph nodes. They do not
  establish API latency, database size, process RSS or a supported estate limit.
- SQLite and PostgreSQL own graph persistence. ClickHouse is an optional event
  analytics sink, not a graph-store replacement. See [storage backends](STORAGE_BACKENDS.md).
- Size a deployment using its unique nodes and edges, retained snapshots,
  concurrent scans and queries. Measure full-process memory, storage growth and
  end-to-end p95 latency against the intended database before setting capacity.

Run yourself:

```bash
pip install 'agent-bom[dev]'
pytest tests/benchmarks/test_graph_hot_paths.py --benchmark-only
AGENT_BOM_BENCH_FULL=1 pytest tests/benchmarks/test_graph_hot_paths.py -k 50k --benchmark-only
```

---

## End-to-end scan targets

These aren't micro-benchmarks yet; they're the target envelope the
team runs against during pilot smoke-testing. Run
`scripts/pilot-verify.sh` to check your own environment.

| Operation | Target (pilot) | Target (production) |
|---|---:|---:|
| `/healthz` round-trip | < 20 ms p99 | < 50 ms p99 |
| `/v1/fleet/sync` single heartbeat | < 100 ms p99 | < 200 ms p99 |
| `/v1/compliance` aggregate across 100 scan jobs | < 500 ms p99 | < 1 s p99 |
| `/v1/compliance/{framework}/report` at 10k findings | < 150 ms p99 | < 300 ms p99 |
| `/v1/compliance/{framework}/report` at 50k findings | < 500 ms p99 | < 1 s p99 |
| jsonl bundle streaming (first byte) | < 50 ms | < 100 ms |

## Graph and control-plane operator targets

These are the target envelopes for the main operator flows after the
0.81.x store-backed graph improvements. They are not yet universal
guarantees for every tenant shape; they are the thresholds we expect a
healthy self-hosted rollout to validate with the bundled k6 harness.

| Operation | Baseline path | Target (pilot) | Target (production) |
|---|---|---:|---:|
| `GET /v1/graph?limit=100` | store-backed overview page | < 300 ms p95 | < 500 ms p95 |
| `GET /v1/graph/search?q=agent&limit=25` | store-backed search page | < 250 ms p95 | < 400 ms p95 |
| `GET /v1/graph/attack-paths?limit=25` | persisted-path queue with path-edge envelope | < 150 ms p95 | < 300 ms p95 |
| `GET /v1/fleet?limit=25` | authenticated fleet read | < 200 ms p95 | < 350 ms p95 |
| `GET /v1/fleet/stats` | fleet summary read | < 150 ms p95 | < 300 ms p95 |
| `POST /v1/proxy/audit` | proxy audit ingest batch | < 300 ms p95 | < 500 ms p95 |

### How to measure the operator targets

Run against the deployment you actually intend to operate:

```bash
export AGENT_BOM_BASE_URL=https://agent-bom.internal.example.com
export AGENT_BOM_API_TOKEN=replace-me
export AGENT_BOM_GRAPH_SCAN_ID=$(curl -s -H "Authorization: Bearer $AGENT_BOM_API_TOKEN" \
  "$AGENT_BOM_BASE_URL/v1/graph/snapshots?limit=1" | jq -r '.[0].scan_id')

k6 run deploy/loadtest/k6-control-plane-api.js
k6 run deploy/loadtest/k6-graph-api.js
k6 run deploy/loadtest/k6-proxy-audit.js
```

The v0.102.0 release-candidate measurement on the local 6.8k-node demo
snapshot returned 25 persisted paths in 38.4–39.7 ms after warm-up. Restricting
the response to the edges that prove those paths reduced the envelope from
508,562 to 192,879 bytes while direct-neighbor traversal remained available
through the node-neighbor endpoint. Raw samples and scope are recorded in
[`perf/results/attack-path-queue-envelope-live-2026-08-22.json`](perf/results/attack-path-queue-envelope-live-2026-08-22.json).

Interpretation:

- if graph overview/search breaches target first, keep the graph windowed by
  snapshot and page size before widening runtime rollout
- if fleet reads breach target first, tune API HPA and database size before
  assuming the graph is the bottleneck
- if proxy audit ingest breaches target first, adjust batch size, retention,
  or analytics backend before widening sidecar/gateway deployment

Latency budget for a bundle export at 50k findings on Postgres:

- `_tenant_jobs` store read: ~10 ms (index on tenant_id)
- `_index_blast_radii_by_tag` in process: ~44 ms (measured above)
- `_evidence_for_control` × 220 controls: ~30 ms (O(tags × findings-per-tag))
- Canonical JSON + sign: ~20 ms (measured above)
- **Total: ~104 ms at p50, well inside the 500 ms p99 target**

---

## CPU / memory sizing

Pilot-default Helm values ([`eks-mcp-pilot-values.yaml`](../deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml)):

| Component | Request / Limit | Notes |
|---|---|---|
| `agent-bom-api` | 500 m / 2 CPU, 512 Mi / 2 Gi | 2–6 replicas via HPA |
| `agent-bom-ui` | 100 m / 500 m CPU, 256 Mi / 1 Gi | Next.js SSR |
| `scan` CronJob | 1 CPU / 4 CPU, 1 Gi / 4 Gi | Runs every 6 h |
| `agent-bom-proxy` sidecar | 100 m / 500 m CPU, 128 Mi / 512 Mi | Per-MCP |

Scale-out signal: `agent_bom_rate_limit_hits_total` hitting a tenant
bucket for > 10 minutes, OR `p95` on `/v1/compliance/*` above 800 ms.
Both show up on the shipped Grafana dashboard.

For graph/runtime-heavy rollouts, treat these as the next scale-out
signals too:

- `/v1/graph` `p95` consistently above `500 ms`
- `/v1/graph/search` `p95` consistently above `400 ms`
- `POST /v1/proxy/audit` `p95` consistently above `500 ms`
- rising queueing or timeout behavior during the bundled k6 graph/control-plane runs

---

## Storage growth

Rough per-tenant rates observed during pilot runs:

| Backend | Scan jobs | Fleet agents | Audit events |
|---|---:|---:|---:|
| Postgres | ~3 KB / job | ~1 KB / agent | ~0.5 KB / event |
| ClickHouse | ~1.5 KB / row (compressed) | n/a | ~0.5 KB / event |
| Snowflake | ~2 KB / row (Hybrid Tables) | ~1 KB / agent | ~0.5 KB / event |

A pilot tenant with **200 agents, a scan per agent every 6 h, and
1,000 audit events per hour** produces:

- 800 scan jobs / day (~2.4 MB Postgres, ~1.2 MB ClickHouse, ~1.6 MB Snowflake)
- 200 fleet agents steady-state (~200 KB)
- 24,000 audit events / day (~12 MB)

TTL + retention knobs: `AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT`
(default 1000), `AGENT_BOM_AUDIT_RETENTION_DAYS` (default 90).

The per-job rates above cover job metadata only. A pushed job also stores its
full result and graph snapshot; the measured growth for a 200-agent push is in
the next section.

---

## End-to-end workflow budgets

Component benchmarks above time one function. This section measures one complete
workflow in one process: collect → scan and enrich → push ingest → retained
storage → graph and API reads → report export → retention → rebuild, plus a
restart, a SIGKILL during ingest, and two concurrent API processes.

**Profiles** (`scripts/perf/workflow_profiles.py`): the estate comes from
`scripts/generate_graph_benchmark_estate.py`, seed 2145, 8% vulnerable packages.
It becomes a schema-valid `--inventory` file, and OCI image references are
dropped because an inventory cannot carry them.

| Profile | Agents | Store | API processes | Concurrent pushes | Reads per endpoint | CPU / memory envelope |
|---|---:|---|---:|---:|---:|---|
| `ci-budget` | 12 | SQLite | 1 | 1 | 8 | 2 CPU / 2 GiB |
| `small-self-hosted` | 200 | SQLite | 1 | 1 | 30 | 2 CPU / 2 GiB |
| `small-self-hosted-postgres` | 200 | Postgres 16 | 1 | 1 | 30 | 2 CPU / 2 GiB |
| `multi-replica-local` | 200 each | Postgres 16 | 2 | 2 | 30 | 2 CPU / 2 GiB each |

The envelope matches the pilot Helm API limit. It is checked against the
measured numbers, not enforced: macOS has no cgroups.

**How it runs.** The real `agent-bom agents --inventory` command scans the
estate. Every advisory, registry and KEV client is routed to a counting mock
(`MockUpstream`), and a socket guard refuses and records any non-loopback
connection; every run below recorded zero. The first OSV batch call returns
503 so the client retry path runs. The API is the real ASGI app over SQLite
files or `AGENT_BOM_POSTGRES_URL`. The findings report is built by the embedded
report runner, because the in-process transport does not start the worker loop.
Retention is the API maintenance sweep (`expire_jobs_and_snapshots`) with its
TTL set to zero. The finding set `(advisory, package, version)` is compared
exactly against the fixture after the scan, after storage, after the rebuild,
across a restart and after a killed ingest.

```bash
python scripts/run_workflow_resource_benchmark.py --profile small-self-hosted --output /tmp/wf.json
# Postgres: migrated database, app and maintenance roles
AGENT_BOM_POSTGRES_MAINTENANCE_URL=postgresql://maint:...@127.0.0.1:PORT/agent_bom \
  python scripts/run_workflow_resource_benchmark.py --profile small-self-hosted-postgres \
  --profile multi-replica-local --postgres-url postgresql://app:...@127.0.0.1:PORT/agent_bom
```

Each phase runs in its own child process, so CPU-seconds and max RSS are the
child's own `wait4` rusage. The runner exits non-zero if any phase crashes,
any finding set differs, or any outbound connection is attempted.

**Measured 2026-11-11** on an Apple M4 (10 cores, 16 GiB, macOS 27.0.1,
Python 3.13.5, PostgreSQL 16.14 on loopback). The host was shared with other
workloads (load average 5-9), so wall time is noisy and CPU-seconds are the
primary signal. Raw results:
[`perf/results/workflow-resource-budget-2026-11-11.json`](perf/results/workflow-resource-budget-2026-11-11.json).

Cold run, 200 agents, 4,058 packages, 207 findings, 11,490 graph nodes:

| Stage | SQLite CPU s | Postgres CPU s | Notes |
|---|---:|---:|---|
| Collection | 0.5 | 0.5 | 467 KB inventory |
| Scan + enrichment | 25.9 | 21.6 | 268 upstream requests: 5 OSV batch calls (one an injected 503, retried), 207 advisory details, 56 capped registry/advisory/KEV lookups; JSON report 73.4 MB |
| Push ingest | 60.2 | 46.8 | 147 MB sent (push + identical retry); admission 5.6 s; retry returned the same job |
| Graph and API reads (150) | 33.4 | 22.2 | see latency below |
| Report export | 17.1 | 12.4 | graph JSON 9.4 MB (5.5-7.4 s), GraphML 15.2 MB (5.2-8.0 s), findings NDJSON 0.68 MB (~2 s) |
| Retention sweep | 0.05 | 0.01 | |
| Rebuild (re-ingest) | 70.7 | 50.9 | |
| **Whole child process** | **225** | **165** | peak RSS 1,661 / 1,874 MiB; steady (median during reads) 587 / 1,227 MiB |

Read latency, cold-run process (p50 / p95 ms, nearest rank over 30 reads; bytes per response):

| Read | SQLite | Postgres | Response |
|---|---:|---:|---:|
| `GET /v1/graph?limit=100` | 234 / 2,694 | 173 / 840 | 2.6 MB |
| `GET /v1/graph/search?q=agent&limit=25` | 94 / 2,810 | 73 / 155 | 66 KB |
| `GET /v1/graph/attack-paths?limit=25` | 84 / 1,207 | 68 / 732 | 512-542 KB |
| `GET /v1/findings?limit=100` | 114 / 1,556 | 96 / 720 | 362 KB |
| `GET /v1/jobs?limit=25` | 10 / 28 | 11 / 22 | < 1 KB |

Storage:

| | SQLite | Postgres |
|---|---:|---:|
| First push (fresh store) | +94.4 MB (WAL 11.1 MB) | +113.4 MB database, indexes 3.1 → 64.6 MB, 291.6 MB WAL written |
| Second identical-estate push (warm) | +75.1 MB | +36.7 MB database, +31.9 MB indexes, 336 MB WAL |
| After expiring every job | no shrink (94.8 / 175.9 MB) | no shrink (129.9 MB) |

Writes cost more than reads: Postgres writes about 2.6x the database growth as
WAL. Retention frees pages for reuse, but files do not shrink without
`VACUUM`. Size the volume for peak retained jobs, not for the post-sweep count.

Cold, warm, restart, cancellation and replicas:

- **Warm** (same store, warm scan cache): upstream requests fell from 268 to 56,
  because OSV batch and detail calls were answered from cache. Scan CPU did not
  fall (29.6 s SQLite, 20.2 s Postgres), so scan cost is local analysis, not
  network.
- **Restart** (new process, same store): the stored finding digest matched the
  run before the restart on both stores. The first `/v1/graph` read returned
  **503 after 2.3 s** while the graph warmed. Afterwards, graph page p50 was
  1.0-1.4 s (vs 0.17-0.23 s in a warm process), with p95 1.3-2.0 s.
- **Cancellation** (SIGKILL right after the async push was admitted): the job was
  left `pending`, and both SQLite files passed `PRAGMA integrity_check`. The
  identical retry in a new process kept the same job id and was stored in 44 s
  on SQLite and 54 s on Postgres, with exactly the expected 207 findings.
- **Two API processes, one Postgres**: each pushed its own estate concurrently.
  Both stored exactly their expected findings (207 and 209). Each process used
  167-169 CPU-seconds with peak RSS 1,656-1,706 MiB; the pair took 179 s wall.
  The database grew 183-190 MB across both pushes, with about 1.1 GB of WAL.

Findings from these runs:

- **Memory headroom is thin.** Peak RSS was 1.66 GiB on SQLite and 1.87-1.97 GiB
  on Postgres, against a 2 GiB limit, for one 200-agent push plus a rebuild in
  the same process. The peaks come from ingest and rebuild of the 73 MB report.
  Larger estates need more memory, or ingest moved to a worker process
  (`AGENT_BOM_API_ROLE=worker`).
- **The report payload dominates bytes.** The CLI JSON report is about 367 KB
  per agent, and it is sent twice when a client retries.
- **The graph page grows with retained data.** `GET /v1/graph?limit=100` returned
  2.6 MB, then 4.1 MB, then 6.7 MB as more jobs were stored, at the same limit.
- **An identical re-push after retention is refused.** Once retention expires a
  pushed job, an identical async push returns `409 ... no longer retained; push
  again` on every attempt. The content idempotency key stays live for
  `AGENT_BOM_IDEMPOTENCY_TTL_HOURS` (default 24), so "push again" cannot succeed
  with the same content. A fresh `Idempotency-Key` works, and the rebuild above
  uses one.

**PR regression budget** (`tests/test_workflow_resource_budget.py`, runs in the
isolated `graph_performance` CI step, about 20 s locally): `ci-budget` profile,
fresh SQLite. Accuracy and request-shape checks are exact. Resource ceilings
are several times the measurement, so a 4-vCPU runner does not flake:

| Budget | Measured | Ceiling | Why this margin |
|---|---:|---:|---|
| Finding sets (scan = fixture, store = scan, rebuild = store) | 35 = 35 = 35 | exact | accuracy is not a tolerance |
| Outbound connections | 0 | 0 | offline proof |
| Upstream requests per package | 0.16 (93 / 573) | 0.5 | a new per-package call adds ≥ 1 per package |
| JSON report | 10.6 MB | 24 MiB | sizes are near-deterministic; ~2x |
| SQLite growth per push | 13.9 MB | 32 MiB | ~2x |
| Largest read response | 2.0 MB | 4 MiB | ~2x |
| Read p95 (8 samples, effectively max) | ≤ 2.0 s | 8 s | catches stalls only; latency is not a PR SLO |
| CPU-seconds per stage | 0.03-5.5 | 2-25 | 3-5x for runner variance |
| Whole run CPU-seconds | 17-27 | 90 | 3-5x |
| Peak RSS | 410-540 MiB | 1,536 MiB | profile limit less runner headroom |

The `small-self-hosted` SQLite profile runs nightly in `perf-scale-evidence.yml`
(job `workflow-resource-budget`, or dispatch with `workflow_budget`). That job
fails on any crash, finding mismatch or outbound connection; it has no timing
gate.

**Not measured here:** a real multi-node Kubernetes deployment, or replicas
behind a load balancer (the replicas above are two local processes on one
host); Postgres under the nightly job (it needs the migration and role setup
from `postgres-scale-evidence.yml`); query plans and index choice for these
reads (see `scripts/run_graph_postgres_explain.py`); migration cost; enforced
cgroup CPU and memory limits; estates beyond 200 agents per push; and any
monetary cost, because no provider prices were used.

---

## Adding a benchmark

1. Add a test under `tests/benchmarks/test_<area>.py` using the
   `benchmark` fixture from pytest-benchmark.
2. Parametrize by scale (1k / 10k / 50k) so we see the curve. Guard the
   50k variant with `@pytest.mark.slow` and the `AGENT_BOM_BENCH_FULL=1`
   env skip.
3. Run `pytest tests/benchmarks/ --benchmark-only --benchmark-json=bench.json`,
   paste the numbers here with the measurement date.
4. Update the "Implication for pilot teams" sentence — numbers without
   an operator narrative are numbers the on-call will ignore.

Benchmarks are not part of the default CI gate — they run on demand via
`workflow_dispatch` on the same runner family so results stay
comparable.
