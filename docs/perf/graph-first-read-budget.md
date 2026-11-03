# First graph and findings read budgets

Run the PR-sized synthetic workload in the same Python environment as CI:

```bash
uv run pytest -q -s tests/api/test_graph_first_read_budget.py --junitxml=/tmp/graph-read-budget.xml
```

The console and JUnit properties contain fixture counts, Python/platform,
individual request durations, payload bytes, SQLite statements and fetched
rows, concurrent health timings, and peak Python allocations. The affected-test
CI job runs this file separately on shard zero, without xdist or coverage; its
performance marker excludes it from the competing parallel test workers. It
uses the estate generator with seed
2145 at 12 and 120 agents; **10x means agents, not graph nodes**. Inspect the
recorded node, edge, package, server and finding counts before comparing runs.

Cold means a new current-estate projection and empty process response caches.
The operating-system page cache is not flushed. The ASGI client shares the
application event loop with health probes. Durations include database work,
serialization and in-process transfer; they exclude external network latency
and browser layout/paint. The test measures allocations in a separate request
so tracing does not inflate the latency samples.

Each fixture reads a 100-node raw graph page, a 100-node canvas page, a 100-entry
rollup page and a 50-finding page. The first request and five warm samples are
retained separately. Warm p50/p95/p99 use the existing benchmark percentile
helper; five samples are a regression signal, not a reliable tail-latency SLO.

The enforced limits are under two seconds and two million payload bytes for
each read, one second for each concurrent health request, and 32 million bytes
of peak Python allocations for a warm graph read. Every read must execute fewer
than 1,000 statements and fetch fewer than 80,000 rows; warm reads must execute
fewer than 200 statements and fetch fewer than 2,000 rows. A new complete scan
must invalidate the current generation, and a foreign tenant must not receive
the seeded graph.

Two further cases admit an asynchronous push at each size while probing health,
graph and findings. They require a durable stored receipt, idempotent replay,
generation refresh and a foreign-tenant denial. A refresh waits at most 50 ms
when a prior complete graph exists, reports `previous_generation` while the
worker finishes, and leaves graph reachability unassessed during that interval.
The cold-start build allowance remains two seconds; explicit snapshots remain
exact reads. These are request budgets, not ingest-completion deadlines.

For the browser, run `npx playwright test e2e/graph-paint-budget.spec.ts` from
`ui/` after a production build. It measures navigation through settled camera
and two animation frames, checks that the visible cards fit, and retains
screenshots plus p50/p95/p99 JSON receipts. Each case uses ten fresh-context and
ten reused-context samples. The synthetic source contains one workspace and
12 or 120 MCP servers, capped at 100 returned nodes. This is a different fixture
from the API's 12/120 **agents**. Intercepted responses isolate JavaScript,
layout and paint; routing disables the browser HTTP cache, and the measurement
excludes backend construction and external network latency. It is included in
the PR browser smoke command. Ten samples do not establish a tail-latency SLO.

Next, repeat on a dedicated host, record CPU/RAM and revision, and increase the
sample count. For
sustained concurrent ingestion and larger populations, use
[the mixed-load workload](graph-mixed-load.md). These budgets do not establish
production capacity or a customer deployment SLO.
