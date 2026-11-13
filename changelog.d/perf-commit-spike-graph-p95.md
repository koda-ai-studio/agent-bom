### Performance
- Large estates read their graph much sooner after a push. Whole-snapshot graph writes and loads on SQLite hold a 64 MiB page cache while they run, and tool capability classification is cached and matched in one pass. At 5,000 agents (170,330 graph nodes) the performance qualification lane measured the first graph read at 11.6 s instead of 27.8 s and the graph p95 at 3.1 s instead of 18.3 s; these are single runs on a shared, heavily loaded host.
- A push that lands while its tenant's current graph is being rebuilt now queues exactly one follow-up rebuild, however many pushes arrive, so the next reader no longer pays for that rebuild itself.

### Docs
- Performance and sizing lists measured graph and findings read latency per estate size and the measured SQLite peak memory range.

### CI
- The performance qualification lane records the API's peak memory on macOS too (sampled where `/proc` is absent) and says which method produced each value.
