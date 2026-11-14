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
| `GET /v1/graph?limit=100` | current-estate overview page, steady state | < 2 s p95 | < 2 s p95 |
| `GET /v1/graph/search?q=agent&limit=25` | store-backed search page | < 1 s p95 | < 1 s p95 |
| `GET /v1/graph/attack-paths?limit=25` | persisted-path queue with path-edge envelope | < 150 ms p95 | < 300 ms p95 |
| `GET /v1/fleet?limit=25` | authenticated fleet read | < 200 ms p95 | < 350 ms p95 |
| `GET /v1/fleet/stats` | fleet summary read | < 150 ms p95 | < 300 ms p95 |
| `POST /v1/proxy/audit` | proxy audit ingest batch | < 300 ms p95 | < 500 ms p95 |

The graph rows were 300/500 ms (overview) and 250/400 ms (search) p95 until
2026-11-13, when the qualification lane showed they were not met at 1,000 or
5,000 agents. The measured values and the first-read target after a push are in
[Performance and sizing](../site-docs/deployment/performance-and-sizing.md#target-operator-latency-envelope).

#### Qualification lane, 2026-11-13

`python scripts/qualification/performance.py --backend {sqlite,postgres} --estates medium-1000-agents,large-5000-agents --scale-budget-seconds 0`,
alternating `main` (bebdb0f6a) and this change, PostgreSQL 16 in a private
local cluster, shared 10-core macOS host (1-minute load 2.9 to 8.8). Median
(range) of three runs, four for PostgreSQL at 5,000 agents; times in ms,
memory sampled every 100 ms:

| Backend | Agents | Tree | First read | Graph p50 | Graph p95 | Findings p95 | Push stored (s) | Peak RSS (MB) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQLite | 1,000 | main | 2,517 (2,083–3,336) | 523 (492–595) | 1,703 (1,484–2,130) | 1,646 (946–2,061) | 42 (37–51) | 699 (626–704) |
| SQLite | 1,000 | change | 1,034 (978–1,115) | 449 (420–1,080) | 1,789 (978–2,049) | 76 (45–940) | 40 (40–46) | 663 (630–826) |
| SQLite | 5,000 | main | 19,899 (15,321–29,274) | 817 (390–861) | 5,652 (1,382–6,249) | 2,107 (2,073–3,045) | 256 (205–323) | 1,687 (1,570–1,925) |
| SQLite | 5,000 | change | 4,492 (4,193–8,147) | 366 (303–664) | 483 (411–1,177) | 2,053 (2,032–2,079) | 349 (189–482) | 1,313 (1,215–1,549) |
| PostgreSQL | 1,000 | main | 1,915 (1,831–2,156) | 464 (461–473) | 1,762 (1,700–1,823) | 505 (175–564) | 62 (61–63) | 716 (696–724) |
| PostgreSQL | 1,000 | change | 1,368 (1,368–1,424) | 513 (371–535) | 1,650 (1,368–1,754) | 543 (84–613) | 60 (59–66) | 802 (762–837) |
| PostgreSQL | 5,000 | main | 7,459 (6,801–7,886) | 412 (335–1,313) | 6,254 (5,752–8,219) | 2,073 (119–2,168) | 329 (322–376) | 1,973 (1,918–2,070) |
| PostgreSQL | 5,000 | change | 3,776 (3,641–3,903) | 960 (332–1,578) | 7,797 (5,346–9,573) | 1,158 (146–2,087) | 320 (316–330) | 2,019 (1,976–2,065) |

Push-stored time on SQLite at 5,000 agents tracked host load in both trees
(the change measured 189 s at load 3.6 against 205 s for `main` at load 2.9).
On PostgreSQL at 5,000 agents the graph p95 comes from the first 30 to 40
seconds after the push, on both trees; reads after that measured about 0.3 s.

#### Qualification lane on GitHub runners, 2026-11-13

Qualification workflow, `lanes=performance`, one run per tree on
`ubuntu-latest` (4 vCPU), PostgreSQL in a service container on the same runner.
`main` is the tree before the change; the change is run 43539497718, which also sampled the API's
stacks (`stack_samples=true`). Times in ms:

| Backend | Agents | Tree | First read | Graph p50 | Graph p95 | Graph max | Findings p95 | Peak RSS (MB) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQLite | 1,000 | main | 3,947 | 650 | 2,237 | 3,947 | 1,272 | 670 |
| SQLite | 1,000 | change | 999 | 320 | 999 | 1,911 | 46 | 727 |
| SQLite | 5,000 | main | 26,905 | 521 | 8,475 | 26,905 | 2,046 | 1,975 |
| SQLite | 5,000 | change | 8,585 | 368 | 561 | 8,585 | 2,031 | 1,544 |
| PostgreSQL | 1,000 | main | 1,844 | 751 | 1,844 | 4,038 | 439 | 719 |
| PostgreSQL | 1,000 | change | 2,663 | 1,060 | 2,663 | 2,926 | 77 | 826 |
| PostgreSQL | 5,000 | main | 7,884 | 602 | 7,884 | 8,988 | 2,295 | 2,181 |
| PostgreSQL | 5,000 | change | 5,823 | 760 | 6,960 | 9,470 | 2,109 | 2,209 |

The stack samples place the PostgreSQL stalls beside the first current-estate
build: the reads ask for an explicit scan, so they query PostgreSQL directly,
while the build thread decodes the whole snapshot from PostgreSQL
(`postgres_graph.load_graph`) and writes the SQLite projection, both
CPU-bound under the same interpreter lock. At 5,000 agents that covers the
first seven reads; at 1,000 agents the build ran through all 20, which is why the
change's 1,000-agent median is above `main`'s. Findings p95 at 5,000 agents is
the 2 s read-your-writes wait for that build on both trees.

Making that build pause for in-flight requests was tried (run 43544910722) and
reverted: it stretched the contention across every read, taking the PostgreSQL
5,000-agent median from 760 ms to 1,847 ms and the 1,000-agent median to
1,258 ms. The remaining fix is to copy a single-source PostgreSQL projection as
rows rather than through graph objects, as SQLite sources already are.

#### PostgreSQL row copy on GitHub runners, 2026-11-14

Three rounds of the Qualification workflow (`lanes=performance`), each running
`main` at 2d20563a9 and the row-copy change (a13fad5ce, whose only parent is
2d20563a9) side by side. Median (range) of three runs; times in ms:

| Backend | Agents | Tree | First read | Graph p50 | Graph p95 | Graph max | Findings p95 | Peak RSS (MB) | Push stored (s) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PostgreSQL | 1,000 | main | 2,448 (2,087–3,156) | 1,075 (685–1,118) | 2,302 (2,087–3,077) | 3,156 (2,448–3,532) | 75 (56–80) | 795 (773–810) | 109 (87–113) |
| PostgreSQL | 1,000 | change | 1,264 (750–1,347) | 738 (726–820) | 934 (851–1,264) | 1,347 (907–1,538) | 211 (160–336) | 811 (790–813) | 67 (62–89) |
| PostgreSQL | 5,000 | main | 6,519 (5,859–6,795) | 1,473 (860–1,898) | 7,014 (5,859–7,102) | 7,661 (6,664–9,135) | 2,087 (1,107–2,121) | 2,207 (2,206–2,214) | 567 (440–579) |
| PostgreSQL | 5,000 | change | 5,056 (4,475–6,495) | 1,502 (1,453–2,143) | 2,363 (1,776–4,475) | 5,611 (5,056–6,495) | 570 (106–615) | 1,526 (1,487–1,533) | 344 (320–463) |
| SQLite | 1,000 | main | 1,038 (1,002–1,598) | 334 (326–436) | 1,314 (1,038–1,598) | 2,429 (1,517–2,825) | 35 (27–48) | 731 (712–744) | 28 (28–44) |
| SQLite | 1,000 | change | 1,389 (1,265–1,897) | 611 (530–623) | 1,389 (1,265–1,897) | 3,099 (3,019–3,444) | 61 (47–66) | 823 (820–837) | 46 (44–50) |
| SQLite | 5,000 | main | 7,886 (7,082–10,490) | 439 (395–498) | 549 (520–739) | 7,886 (7,082–10,490) | 2,056 (2,054–2,121) | 1,620 (1,612–1,642) | 152 (151–239) |
| SQLite | 5,000 | change | 10,672 (9,854–13,764) | 594 (560–608) | 702 (678–1,235) | 10,672 (9,854–13,764) | 2,091 (2,087–3,453) | 1,618 (1,617–1,688) | 267 (233–274) |

On PostgreSQL the reads of 4.6 to 9.1 s in the first five reads after a
5,000-agent push are gone, the findings p95 there falls from 2.1 s to 0.57 s,
and peak API memory falls by 680 MB, since no graph objects are built. The
1,000-agent median is 0.74 s against `main`'s 1.08 s. The single-run comparison
above (751 ms on `main` against 1,060 ms) was not a regression: `main`'s own
three-run median is 1,075 ms (685–1,118 ms). The graph p95
at 5,000 agents is 2.4 s, above the 2 s steady-state target: after the first
read, reads take mostly 1.2 to 2.4 s across all 20 on the change, where `main`'s
fell to 0.6 to 0.9 s in two of three runs once its build finished. These runs
did not sample stacks, so what holds those reads is not yet named.

The change does not touch the SQLite path (the copy dispatch for a SQLite store
is unchanged), yet SQLite was slower on the change's runners in all three
rounds, including push ingest (152 s against 267 s at 5,000 agents), which no
part of the change runs. That points to runner variance between the paired jobs
rather than the change, but it was not verified.

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

What the chart renders for the pilot profile
([`eks-mcp-pilot-values.yaml`](../deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml)).
The profile sets no resources, so these are the chart defaults in
`deploy/helm/agent-bom/values.yaml` (checked with `helm template` on 2026-11-11):

| Component | Request / Limit | Notes |
|---|---|---|
| `agent-bom-api` | 100 m / 1 CPU, 512 Mi / 2 Gi | 2 replicas; the HPA (2–6) is off unless `controlPlane.api.autoscaling.enabled` |
| `agent-bom-ui` | 100 m / 500 m CPU, 128 Mi / 512 Mi | Next.js SSR, 2 replicas |
| `scan` CronJob | 50 m / 500 m CPU, 64 Mi / 256 Mi | Every 6 h (`0 */6 * * *`) |
| `agent-bom-proxy` sidecar (injected) | 50 m / 500 m CPU, 64 Mi / 256 Mi | Per MCP workload, set by `sidecar_injector.py` |

The workflow profiles below use a 2 CPU / 2 GiB envelope. The memory limit
matches the API default; the CPU limit is twice it. "Enforced cgroup limits"
below measures both 2 CPU and the 1 CPU default.

Scale-out signal: `agent_bom_rate_limit_hits_total` hitting a tenant
bucket for > 10 minutes, OR `p95` on `/v1/compliance/*` above 800 ms.
Both show up on the shipped Grafana dashboard.

For graph/runtime-heavy rollouts, treat these as the next scale-out
signals too:

- `/v1/graph` `p95` consistently above `2 s` outside the first minute after a large push
- `/v1/graph/search` `p95` consistently above `1 s`
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

The memory envelope matches the chart's API limit (2 Gi); its CPU limit is
1 CPU, not 2. On macOS the runs below check the envelope against measured
numbers only, because macOS has no cgroups. "Enforced cgroup limits" further
down runs the same harness with the kernel enforcing the limits.

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
child's own `wait4` rusage. Since 2026-11-11 the CLI scans (the first scan and
the update/delete rescan) run in a process of their own
(`scripts/perf/workflow_scan_child.py`), as they would on a collector host: the
measured process is the API plus the harness's HTTP client, and the scan
stage reports the scan process's CPU and peak RSS as `scan_process`. Before
that, the scan's own peak (650-800 MiB at 200 agents) and the allocator arenas
it never returned were charged to the API. The runner exits non-zero if any
phase crashes, any finding set differs, any outbound connection is attempted,
any process peaks above 80% of the profile's memory limit (1,638 MiB of
2 GiB), or the restart's first graph read is not 200 after the start-up
prewarm.

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

Findings from these runs, re-checked on 2026-11-11 (see "Product findings,
re-checked" below for the evidence behind each verdict):

- **Memory headroom is thin (confirmed).** Peak RSS was 1.66 GiB on SQLite and
  1.87-1.97 GiB on Postgres, against a 2 GiB limit, for one 200-agent push plus a
  rebuild in the same process. The peaks come from ingest and rebuild of the
  73 MB report. Larger estates need more memory, or ingest moved to a worker
  process (`AGENT_BOM_API_ROLE=worker`).
- **The report payload dominates bytes.** The CLI JSON report is about 367 KB
  per agent, and it is sent twice when a client retries.
- **The graph page grows with retained data (only for unscoped pushes).**
  `GET /v1/graph?limit=100` returned 2.6 MB, then 4.1 MB, then 6.7 MB as more
  jobs were stored, at the same limit. The harness then pushed raw reports with
  no `source_id` or `target_scope`, which the API keeps as independent evidence.
- **An identical re-push after retention was refused** (fixed). Once retention
  expired a pushed job, an identical push returned `409 ... no longer retained;
  push again` for as long as its idempotency key lived
  (`AGENT_BOM_IDEMPOTENCY_TTL_HOURS`, default 24). A replayed key whose job is
  gone now re-admits the same deterministic job, and the rebuild above uses the
  identical push.

**PR regression budget** (`tests/test_workflow_resource_budget.py`, runs in the
isolated `graph_performance` CI step, about 35 s locally): `ci-budget` profile,
fresh SQLite. Accuracy and request-shape checks are exact. Resource ceilings
are several times the measurement, so a 4-vCPU runner does not flake:

| Budget | Measured | Ceiling | Why this margin |
|---|---:|---:|---|
| Finding sets (scan = fixture, store = scan, rebuild = store) | 35 = 35 = 35 | exact | accuracy is not a tolerance |
| Field equivalence after ingest, rebuild and update/delete (see below) | no mismatch | exact | accuracy is not a tolerance |
| Outbound connections | 0 | 0 | offline proof |
| Upstream requests per package | 0.16 (93 / 573) | 0.5 | a new per-package call adds ≥ 1 per package |
| JSON report | 10.6 MB | 24 MiB | sizes are near-deterministic; ~2x |
| SQLite growth per push | 13.9 MB | 32 MiB | ~2x |
| Largest read response | 2.0 MB | 4 MiB | ~2x |
| Read p95 (8 samples, effectively max) | ≤ 2.0 s | 8 s | catches stalls only; latency is not a PR SLO |
| CPU-seconds per stage | 0.03-5.5 | 2-25 | 3-5x for runner variance |
| Whole run CPU-seconds | 17-27; 35 with the update/delete stage | 120 | 3-5x |
| Peak RSS, API process (scan in its own process) | 514 MiB (scan process 134 MiB) | 1,024 MiB | 2x; half the profile limit |
| First zero-wait graph read after a simulated restart and the start-up prewarm | 200 | 200 | exact |

The `small-self-hosted` SQLite profile runs nightly in `perf-scale-evidence.yml`
(job `workflow-resource-budget`, or dispatch with `workflow_budget`). The
Postgres profiles run beside it in `workflow-resource-budget-postgres`: a
Postgres 16 service migrated and role-provisioned exactly as in
`postgres-scale-evidence.yml`, the API connected as the non-superuser
`agent_bom_app`, `small-self-hosted-postgres` and `multi-replica-local`, then
the hot-read plans below. Both jobs fail on any crash, finding mismatch,
equivalence failure, outbound connection, any process above 80% of the
profile's memory limit, a restart whose `/readyz` never answers 200 or whose
first graph read after readiness is not 200, or a removed package still in the
current graph 30 s after the update push is stored. The 30 s refresh bound is
their only timing gate.

### Push admission, start-up readiness and refresh under cgroup limits

Measured 2026-11-12 with `scripts/qualification/cgroup_limits.py` (#6249): the
same harness inside the API image (Python 3.14.8, Alpine) under
`docker run --cpus N --memory 2g --memory-swap 2g`, 200 agents, cold, warm and
restart phases without the cancellation phase, on an Apple M4 shared with
other workloads (load 8-20). "Before" is `main` at `cf833b61f` as recorded in
#6249; "after" is this change. Peak RSS is the measured process (API plus the
harness's in-process HTTP client); peak anonymous memory is the container's.

| Limit | Phase | Peak RSS before | Peak RSS after | Removed package left the current graph after |
|---|---|---:|---:|---|
| 1 CPU / 2 GiB | cold | 1,804 MiB | 1,362 MiB | 30-45 s before; 5.1 s after |
| 1 CPU / 2 GiB | warm | 1,797 MiB | 1,441 MiB | 4.1 s after |
| 1 CPU / 2 GiB | restart | 503 on the first read after 3.2 s, ready at 19 s | `/readyz` 503 `current_graph_prewarming` for 3.4 s, then the first read 200 (2.9 s, no retry) | |
| 2 CPU / 2 GiB | cold | 1,808 MiB | 1,340 MiB | still present at 60 s before; 3.6 s after |
| 2 CPU / 2 GiB | warm | 1,971 MiB | 1,439 MiB | 3.3 s after |
| 2 CPU / 2 GiB | restart | 503 on the first read after 5.8 s, ready at 23 s | `/readyz` 503 for 4.3 s, then the first read 200 (2.7 s, no retry) | |

Peak anonymous memory fell from 1,784 to 1,437 MiB at 1 CPU and from 1,952 to
1,391 MiB at 2 CPU. Every phase now stays under the 1,638 MiB budget (80% of
2 GiB) with about 200 MiB to spare; the largest remaining peak is the warm
phase's graph reads (1,439-1,442 MiB). No OOM kill, findings exact (207) and
every equivalence check passed in both runs. Container CPU-seconds for the
1 CPU run fell from 2,702 to 1,194, partly because the host was less loaded.
An intermediate 1 CPU run with only the admission and readiness changes peaked
at 1,615 (cold) and 1,662 MiB (warm), over budget, and its cold refresh missed
60 s; the warm-up yield and the harness correction below (about 120 MiB of the
remaining drop) account for the rest.

What changed:

- **One parsed copy per push.** For a 50 MiB, 200-agent push the API built a
  JSON-validated model (203 MiB), dumped it for the queued payload (153 MiB)
  and kept the raw body cached on the route's and the body-size middleware's
  request objects until the response. It now parses with the validator's own
  JSON parser (`pydantic_core.from_json`, 78 MiB), validates that data (the
  model shares it, +0.1 MiB), queues the parsed report as the admitted payload
  and drops both cached bodies once parsed. Measured in process: admission
  peak 656 → 452 MiB, push-path peak 1,067 → 784 MiB.
  `tests/test_push_admission_memory.py` holds admission to one parsed copy.
- **The current-graph rebuild runs first and alone.** Graph commit hooks start
  the roll-up and reachability warm-ups from inside the graph write, while the
  ingest still holds its graph and before the job commit; each loaded a second
  full graph beside the ingest and beside the read-triggered rebuild. A push
  commit now queues the rebuild itself, and a warm-up holding its slot waits
  for foreground graph work (persist through commit) and then for current-graph
  builds, within 120 s.
- **Readiness waits for the start-up prewarm** (see
  [RUNTIME_FAIL_MODES.md](RUNTIME_FAIL_MODES.md), "Current graph refresh"). The
  restart phase now polls `/readyz` as the readiness probe does before its
  first read.
- **The harness keeps only the rows it compares.** It held the whole parsed
  scan report (120 MiB) for the run to compare `blast_radius`; as the
  in-process client that was charged to the API. This is a measurement
  correction, not a product change.

### How pushes are modelled

The harness pushes what `agent-bom agents --inventory FILE --no-discover
--push-url` sends (`cli_push_body` in `scripts/perf/workflow_profiles.py`): the
sanitized report plus `source_id` and the `target_scope` the CLI hashes from the
inventory path and collection options. The first version of this harness pushed
the raw report. A push with neither field is independent evidence: it never
replaces an earlier report and never resolves a finding
([`FINDING_LIFECYCLE.md`](FINDING_LIFECYCLE.md#ingest-paths)). Results from the
raw-report runs above are kept as measured; where the push shape changes a
conclusion, the section below says so.

### Equivalence through update, delete, retention and rebuild

`scripts/perf/workflow_equivalence.py` and `workflow_lifecycle.py` compare, per
finding `(advisory, package, version)`, the identity (`canonical_id`,
`package_stable_id`, ecosystem), source (`primary_advisory_source`,
`advisory_sources`, `severity_source`), time (`published_at`, `modified_at`),
scope (`affected_agents`, `affected_servers`, `affected_agent_ids`, `asset`) and
coverage (`advisory_coverage_state`) fields. Each check is exact:

| After | Check |
|---|---|
| Ingest | stored rows equal the scan field for field; `/v1/findings` serves exactly the stored set as open |
| Identical retry | the same job (unchanged) |
| Retention and rebuild | rebuilt rows equal the first stored copy field for field; the open set equals the estate; every `finding_id` and `first_seen` is unchanged |
| Update/delete push (one vulnerable package removed everywhere, another added to one more agent) | stored rows equal the new scan; the open set equals the new estate; the removed finding is `resolved` / `no_longer_detected`; the widened finding's scope carries the new agent; ids and `first_seen` are unchanged; the current graph drops the removed package node |
| Restart | the newest stored job's key and field digests equal the last job the warm run stored |

Measured 2026-11-11, 200 agents, Postgres 16 migrated to `20261111_01`, cold
run: all checks passed. After the update push, the current graph dropped the
removed package after **13.1 s** (0.7 s at 12 agents) because it rebuilds
asynchronously; the removed finding left the open set at once.

Two behaviours the checks surfaced:

- **A resolved finding lost its package identity** (fixed). `/v1/findings?status=resolved`
  served the row with `package`, `package_version`, `ecosystem` and `scan_id`
  null. They are now served, with `resolved_by_scan_id`, and the harness fails
  the update stage if any is missing.
- **An older report delivered after a newer one.** Pushing the original report
  again after the update push (new key, older `generated_at`) left the finding
  `resolved`, as the lifecycle rules say: evidence time wins over arrival. The
  current graph, which follows the latest stored job, showed the removed package
  again. Findings and graph disagree until the next current push. Measured on a
  12-agent SQLite store. Not reproduced on 2026-11-11 at 4 agents on SQLite: the
  current graph selects each scope's newest report by its own time, and
  `tests/test_workflow_push_lifecycle_gaps.py` guards it nightly.

A third behaviour explained the raw-push graph growth: **agent ids embedded a
hash of the inventory file path** (fixed). An inventory agent without its own
`config_path` is now identified without the inventory path, and reports carry
the earlier id in `previous_canonical_ids` and `previous_graph_ids`.

### A larger push: 1,000 agents

Profile `large-push-sqlite` (1,000 agents, 19,105 packages, 827 findings), one
cold run on SQLite under a 9 GiB RSS watchdog. **It does not fit in one push.**
The CLI JSON report is 330 MB (about 330 KB per agent). The API refused it with
`413`: it is over the default `AGENT_BOM_API_RESULT_PUSH_MAX_BYTES` (192 MiB),
and over the 240 MiB cap that setting allows, so no configuration accepts it.
The scan alone peaked at 2,431 MiB RSS, above the 2 GiB pilot limit, before
ingest started; the run took 256 s to the rejection. An estate this size has to
be pushed in several scans of at most about 550 agents each, by the 192 MiB
default and this fixture's report size.

The cap is a storage limit, not a transport one: one push is stored as one job
result, which must fit PostgreSQL's jsonb value limit, so chunking one report
into parts would only move the refusal to the commit. Since 2026-11-11 the CLI
says so before it costs an upload. It measures the serialized report; past
240 MiB it sends nothing, and on a 413 it reads the server's `max_bytes` and
does not retry. The run fails with, for this fixture, "The report is 314.7 MiB
decoded (1,000 agents); this control plane accepts at most 192.0 MiB per push
... Push at most 549 agents per push: split the inventory into files of that
many agents and run one scan per file". Each inventory path is its own target
scope, so each file's next push replaces only its own evidence and the current
estate is their union. Guarded by `tests/test_push_size_limit.py`.

### Postgres query plans and tenant-scoped indexes

The statements behind the hot reads were taken from `pg_stat_statements` while
the harness served `/v1/findings`, `/v1/inventory/assets`, `/v1/graph`,
`/v1/graph/search`, `/v1/graph/incident-edges`, `/v1/graph/attack-paths`,
`/v1/jobs` and `/v1/reports/{id}` on the 200-agent store. They are listed in
`scripts/perf/postgres_hot_reads.py`, which imports the application's own SQL
fragments where it has them, and explained with `EXPLAIN (ANALYZE, BUFFERS)` as
`agent_bom_app` with `app.tenant_id` set, so row-level security is in the plan:

```bash
python scripts/run_graph_postgres_explain.py --run --hot-reads --hot-reads-only \
  --dsn postgresql://agent_bom_app:...@HOST/agent_bom --output-dir /tmp/plans --summary-output /tmp/plans.json
```

With a single tenant, every row is that tenant's, so a plan that ignores the
tenant looks the same as one that uses it. The estate's hot-table rows were
therefore copied into three more tenants and the database analyzed (four
tenants, 22,980 graph nodes, 25,480 edges and 3,712 lifecycle rows each; 880 MB).
`scripts/perf/postgres_plans.py` flags a sequential scan of a tenant table past
1,000 examined rows and any index on a tenant table whose leading key is not
`tenant_id` or `team_id`.

| Read | Statement | Plan (four tenants) | Rows | ms |
|---|---|---|---:|---:|
| `/v1/findings` | live lifecycle rows | bitmap `idx_finding_lifecycle_last_job` | 3,712 | 2.7 |
| `/v1/findings` | lifecycle payloads by key | `finding_lifecycle_pkey` | 23 | 0.1 |
| `/v1/findings` | job payload | sequential, `scan_jobs` (under 30 rows) | 1 | 11 |
| `/v1/inventory/assets` | inventory page | `idx_pg_graph_nodes_scan_order` | 102 | 1.3 |
| `/v1/graph` | current-graph node load | bitmap `idx_pg_graph_nodes_scan` | 11,490 | 47 |
| `/v1/graph` | current-graph edge load | bitmap `idx_pg_graph_edges_scan` | 12,740 | 11 |
| `/v1/graph/incident-edges` | out / in seek | `idx_pg_adjacency_out` / `_in` | 1 | 0.05 |
| `/v1/graph/search?q=agent` | match count | bitmap `idx_pg_graph_node_search_severity` | 11,490 | 62 |
| `/v1/reports/{id}` | retained report | sequential, `report_jobs` (8 rows) | 1 | 0.01 |

No hot read scans a tenant table sequentially past the threshold, and every
index used leads with the tenant. Raw plans and reviews:
[`perf/results/workflow-postgres-plans-2026-11-11.json`](perf/results/workflow-postgres-plans-2026-11-11.json).

What the plans also show:

- `/v1/graph` pages do not query Postgres per request. A process loads the whole
  current snapshot once (the node and edge loads above) and serves pages from
  it, so the per-request cost is CPU and memory in the API process, not SQL.
- `/v1/assets` reads the vulnerability-asset tracker, a local SQLite file per
  API process, on every deployment. Pushes do not fill it: on the 200-agent
  Postgres store it returned no assets. The Postgres asset read is
  `/v1/inventory/assets`.
- Graph search uses `idx_pg_graph_node_search_trgm` for selective terms. A GIN
  trigram index cannot lead with `tenant_id` without `btree_gin`, so its
  candidates span every tenant and scan: 144-163 candidate rows for 8 matches
  of `agent-00164` at four tenants. Not changed here.

**Indexes dropped** (migration `20261111_01_drop_redundant_indexes`, guarded by
`tests/test_postgres_redundant_index_migration.py`). None was scanned once after
two full 200-agent pushes and the reads above:

| Index | Why it can never help | Size, four tenants |
|---|---|---:|
| `idx_pg_graph_node_search_lower_trgm` | GIN on `LOWER(search_text)`; `search_text` is stored lowercased and search filters `search_text LIKE`, so the expression never matches | 77 MB |
| `idx_pg_graph_nodes_entity_type` | `entity_type` alone on a tenant table; every read filters tenant and scan first | 848 KB |
| `idx_jobs_team_created`, `idx_jobs_batch`, `idx_jobs_parent`, `idx_jobs_schedule` | column-for-column duplicates of `idx_pg_jobs_*` | 16 KB each |

`init.sql` now creates the `idx_pg_jobs_*` names, and neither bootstrap file nor
the runtime DDL recreates a dropped index. Both bootstrap paths still render one
schema (`check_postgres_schema_parity.py`).

| Write cost per 200-agent push (same database, three pushes each, last pair interleaved) | With | Without |
|---|---:|---:|
| WAL written | 619 / 676 / 658 MB | 401 / 385 / 428 MB |
| `graph_node_search` index size | 175 MB | 97 MB |

That is about 38% less WAL per push. Ingest CPU (43-72 s) was too noisy at load
9-10 to attribute. On a fresh database at the new head, the first 200-agent
push wrote 200 MB of WAL and grew the database by 102 MB, against 292 MB and
113 MB before.

**Migration cost** on the 880 MB, four-tenant database: upgrade 1.1 s wall
(about 0.9 s of that is Alembic start-up) and 0.26 MB of WAL; downgrade, which
rebuilds all six indexes concurrently, 18.1 s and 42 MB of WAL; re-upgrade
1.0 s. Both directions use `CONCURRENTLY`, so no table is locked.

### Product findings, re-checked

| Finding from the first runs | Verdict | Evidence |
|---|---|---|
| Peak RSS 1.66-1.97 GiB against the 2 GiB limit | **Confirmed, and exceeded** | 200 agents on Postgres: cold child 1,804 MiB and warm 1,772 MiB in the raw-push runs; with the update/delete push added (a second scan and push in the same process), the cold process peaked at 2,044.5 MiB. A 1,000-agent scan alone peaked at 2,431 MiB |
| Identical push after retention returns 409 for up to 24 h | **Confirmed, then fixed** | Runs before the fix recorded `409` for raw and CLI-shaped bodies; the push is now stored again (`test_identical_push_after_retention_is_admitted_again`, `tests/api/test_push_replay_after_retention.py`) |
| `GET /v1/graph?limit=100` grows 2.6 → 6.7 MB with stored jobs | **Confirmed only for pushes without `source_id` and `target_scope`** | Three separate scans of one 12-agent estate: unscoped 1.98 → 3.45 MB and 1,630 → 1,849 nodes (agent ids embedded the inventory path hash, so the union held both copies; fixed, see above); CLI-scoped 1.97 MB and 1,630 nodes each time. At 200 agents on Postgres with CLI-scoped pushes the page stayed 2.55 MB across cold, warm and restart. Guarded by `test_rescans_pushed_by_one_cli_source_replace_rather_than_grow_the_graph`. Four identical bodies did not grow it in either mode |
| First `/v1/graph` read after a restart returns 503 | **Confirmed as a timing condition, not on every restart** | A new process builds the current graph on its first read and waits `AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS` (default 2,000 ms); past that it answers `503 current_estate_building` with `Retry-After: 1` while the build finishes. 200 agents on Postgres: raw pushes (two independent reports to merge) 503 after 2.39 s; CLI-scoped pushes (one report) 200 after 1.27 s. At 12 agents both modes returned 200 in under 1.0 s. Larger estates will cross the budget whatever the push shape; nothing prewarms the current graph at start-up |

**Re-measured 2026-11-11 after the fixes** (200 agents, cold / warm / restart
processes, same host at load average 9-15; the CLI scans in their own process,
so the figures are the API plus the harness client):

| | Postgres before | Postgres after | SQLite before | SQLite after |
|---|---:|---:|---:|---:|
| Peak RSS, cold | 1,738 MiB | 1,335 MiB | 1,502 MiB | 1,403 MiB |
| Peak RSS, warm | 1,696 MiB | 1,397 MiB | 1,568 MiB | 1,614 MiB |
| Scan process peak (not in the API) | in process | 276 MiB | in process | 249-270 MiB |
| First `/v1/graph?limit=100` after restart | 200 in 3.4 s, built on read | 200 in 1.0 s | 200 in 3.2 s | 200 in 1.2 s |

The 2,044.5 MiB figure above came from the same profile at higher load; the
peak moves with how background graph work overlaps a push. Where it came from
(labelled RSS timeline): the pushes, not the reads. At each push the server
holds the request body, the validated report and its admission copy, while a
retry of the same body validates and fingerprints a second copy, and the
current-estate rebuild, roll-up warm-up, reachability warm-up and exec warm-up
each load the whole graph or stored evidence on their own threads. Three
changes: the scans moved out of the measured process; the push fingerprint
serializes one field at a time (148 → 53 MiB transient); and the post-commit
warm-ups take turns (one slot, `api/graph_warmup_slot.py`). No record is
dropped; the accuracy and equivalence checks pass in every run. SQLite warm is
still only 24 MiB under the nightly budget: the next cut is push admission,
which keeps the raw body, the validated model and the admission copy alive
together (about 400 MiB at 200 agents).

### Enforced cgroup limits

`scripts/qualification/cgroup_limits.py` runs the same harness inside the API
image with `docker run --cpus N --memory 2g --memory-swap 2g`, so the kernel
enforces the limits (cgroup v2, Docker Engine 29.8.0 in Docker Desktop on Apple silicon,
Python 3.14.8 in the image). It samples `memory.stat` every second and reads
`memory.events` and `cpu.stat` at the end. The limit covers the whole
container: the harness process, the API it hosts and, after #6244, the
separate scan process. Measured 2026-11-11, 200 agents, cold, warm and restart
phases, plus the SIGKILL cancellation where shown. The first two rows are the
image built from `main` at `179801f`, before #6244 moved the scan out of the
measured process and cut push memory; the rows marked "after #6244" are
`main` at `cf833b61f` with this change:

| Profile, limit | OOM kills | Peak anonymous / page cache | Reclaim at the limit (`memory.events max`) | Peak process RSS | CPU throttled | Accuracy and equivalence |
|---|---:|---|---:|---|---|---|
| `small-self-hosted` (SQLite), 2 CPU / 2 GiB, with cancel, before #6244 | 0 | 1,972 / 735 MiB | 8,794 | cold 1,886, warm 1,992 MiB | 36 periods, 3.2 s | all passed; cancel retry converged to 207 findings |
| `small-self-hosted-postgres`, 2 CPU / 2 GiB, with cancel, before #6244 | 0 | 1,797 / 549 MiB | 0 | cold 1,784, warm 1,800 MiB | 26 periods, 0.4 s | all passed; cancel retry converged |
| `small-self-hosted` (SQLite), 2 CPU / 2 GiB, no cancel, after #6244 | 0 | 1,952 / 630 MiB | 6,488 | cold 1,808, warm 1,971 MiB | 255 periods, 4.6 s | findings exact (207); **3 harness failures**, below |
| `small-self-hosted` (SQLite), 1 CPU / 2 GiB (the chart's API limit), no cancel, after #6244 | 0 | 1,784 / 688 MiB | 5,377 | cold 1,804, warm 1,797 MiB | 16,207 periods, 398.6 s | findings exact (207), equivalence passed; RSS budget and restart 503 failed |

What this shows:

- **After #6244 the run is still OOM-free, and the harness's own budget
  fails under the limit.** Peak anonymous memory was 1,952 MiB. The harness
  now fails a process over 80% of the limit (1,638 MiB): cold peaked at
  1,808 MiB and warm at 1,971 MiB, against 1,403 and 1,614 MiB in the
  unconstrained re-measure above. Finding sets stayed exact (207) in both
  processes. Two more failures appear only under the CPU limit: after the
  update/delete push the current graph still held the removed package node
  60 s later (`graph package nodes 1 -> 1`; the rebuild is asynchronous and
  took 13.1 s unconstrained), and after a restart the first graph read
  returned `503 current_estate_building` after 5.8 s despite the start-up
  prewarm, with the graph ready at 23 s. Cold took 1,012 s and warm 1,075 s,
  about twice the pre-#6244 run on the same limit, with this host's other
  benchmark running beside it.
- **At the chart's 1 CPU limit** the workflow also completed without an OOM
  kill (peak anonymous 1,784 MiB) and with exact findings and equivalence;
  the graph refreshed 30-45 s after the update push. It failed the same RSS
  budget (cold 1,804, warm 1,797 MiB) and the restart check (503 after 3.2 s,
  ready at 19 s). The container was throttled for 399 s, warm graph pages
  took 1.7 s p50 and 4.7 s p95 while the process also ingested, and cold and
  warm took 1,128 s and 1,311 s.

- **Before #6244, the 200-agent workflow fit 2 GiB, barely.** Nothing was OOM-killed, but
  the SQLite run's anonymous memory peaked 76 MiB under the limit; the warm
  process's own RSS peaked at 1,992 MiB during its graph reads. The kernel reclaimed page
  cache 8,794 times to stay under it. A slightly larger estate, or a second
  push in flight, will be killed at 2 GiB.
- **Latency under the limit, before #6244.** Warm-process graph page reads were 264 ms p50
  and 3.9 s p95 on SQLite, and 226 ms p50 and 2.9 s p95 on Postgres, while the
  same process ingested and rebuilt; after a restart the p95 fell to 0.8 s and
  0.3 s. The first graph read after a restart returned 503 after 2.7-3.0 s and
  the graph was ready after 4.3-5.5 s.
- **Wall time grows under the CPU limit.** The SQLite cold phase took 562 s and
  the warm phase 839 s at 2 CPU.

**Not measured here:** a multi-node Kubernetes deployment on a cloud provider
(the chart was installed on a one-node kind cluster, see the
[deployment overview](../site-docs/deployment/overview.md#local-live-qualification));
the two-replica profile with CLI-shaped pushes (it runs nightly; locally it was
measured only with raw pushes); SQLite query plans; and any monetary cost,
because no provider prices were used.

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
