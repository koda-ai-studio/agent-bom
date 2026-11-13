### Performance
- Large estates read their graph much sooner after a push. A current estate with one source snapshot on SQLite is copied in SQL instead of being loaded into memory and written back, whole-snapshot graph writes and loads hold a 64 MiB SQLite page cache, matching findings to the servers that host them uses an index instead of scanning every server, and tool classification is cached. In the performance qualification lane at 5,000 agents (170,330 graph nodes) the first graph read after a push fell from 19.9 s to 4.5 s on SQLite and from 7.5 s to 3.8 s on PostgreSQL, the SQLite graph p95 from 5.7 s to 0.48 s, and SQLite peak memory from 1.7 GB to 1.3 GB (medians of three to four runs on a shared, loaded host).
- A push that lands while its tenant's current graph is being rebuilt now queues exactly one follow-up rebuild, however many pushes arrive, so the next reader no longer pays for that rebuild itself.
- SQLite graph stores drop three `graph_edges` indexes that only repeated the leading columns of the adjacency indexes, and Postgres migration `20261113_01` drops the two equivalent Postgres indexes, so every snapshot write maintains fewer indexes.

### Fixed
- Agent context records the snapshot an edge is stored under when the edge carries no source scan, as persistence does; a freshly built graph used to record an empty source scan there.

### Upgrade notes
- Apply Postgres migrations through `20261113_01`. It drops `idx_pg_graph_edges_scan` and `idx_pg_graph_edges_scan_source` `CONCURRENTLY`; its downgrade recreates them.

### Docs
- Performance and sizing lists measured graph and findings read latency per backend and estate size, the measured peak memory range, and graph latency targets the product meets at 1,000 and 5,000 agents in place of the 300/500 ms overview targets it did not.

### CI
- The performance qualification lane records the API's peak memory on macOS too (sampled where `/proc` is absent), reports warm graph reads separately from the first read, and keeps the raw read samples.
