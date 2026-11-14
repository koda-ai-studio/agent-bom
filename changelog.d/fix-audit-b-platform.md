### Upgrade notes
- API SQLite stores now wait at most 5 seconds for a lock (was up to 30), then answer 503 with `Retry-After`. Set `AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS` to change the wait.
- `agent-bom api`, `serve` and `up` no longer write Uvicorn's access line; the API logs each request once, and under `--log-json` the method, path, status, duration and client are `http` keys with request, trace and tenant ids under `context`.

### Fixed
- `/v1/agents` builds for large estates no longer open the shared backpressure breaker and return 429 to every tenant. The `discovery` path gets a 10-second latency threshold, measured against 5,000-agent builds; a pile-up beyond the concurrency limit still sheds.
- A locked or busy SQLite database, or an unreachable PostgreSQL, now returns a 503 JSON error with `Retry-After` and a correlation id within seconds, instead of a plain-text 500 after up to 30 seconds. Any other unhandled error returns a JSON 500 with a generic message and a correlation id, never the exception text.
- The PostgreSQL current-graph copy child reports an unreachable database as such instead of as a role privilege error, and a child that cannot be started falls back to the in-process rebuild.

### Security
- The container's runtime security overlay pins cryptography 50.0.1, matching `uv.lock`; it had installed 50.0.0 over the locked version. A test now fails if any overlay pin is below the lock.
- `agent-bom mcp server --help` and `docs/MCP_SERVER.md` show the bearer token set through `AGENT_BOM_MCP_BEARER_TOKEN`, not on the command line where `ps` shows it.
