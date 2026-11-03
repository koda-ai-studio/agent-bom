# First graph and findings read budgets

Run the PR-sized synthetic workload in the same Python environment as CI:

```bash
uv run pytest -q -s tests/api/test_graph_first_read_budget.py --junitxml=/tmp/graph-read-budget.xml
```

The console and JUnit properties contain fixture counts, Python/platform,
individual request durations, payload bytes, SQLite statements and fetched
rows, concurrent health timings, and peak Python allocations. The test is in
the changed-domain CI smoke selection. It uses the estate generator with seed
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

Next, repeat on a dedicated host, record CPU/RAM and revision, increase the
sample count, and qualify browser first useful rendering independently. For
sustained concurrent ingestion and larger populations, use
[the mixed-load workload](graph-mixed-load.md). These budgets do not establish
production capacity or a customer deployment SLO.
