# GitHub Action

`koda-ai-studio/agent-bom` runs agent-bom in a GitHub Actions job, gates the
build on findings, and publishes SARIF, a job summary and an optional pull
request comment.

## Vulnerability database cache

With `auto-update-db: 'true'` (the default) the scan refreshes the local
vulnerability database at `~/.agent-bom/db/vulns.db` when it misses the daily
freshness target. The Action caches that file under a key with one bucket per
UTC day and restores the newest earlier copy through `restore-keys`:

| Run | What happens | Cost |
|---|---|---|
| Cold (no cache entry yet) | Full database sync, then the cache is saved | Minutes: a full sync of every source measured about 22 minutes and a 2.2 GB database on a developer laptop; runner time varies with network and sources |
| Warm, same day | The day's cache entry is restored; no sync | Cache restore only (proportional to database size) |
| Warm, first run of a new day | Yesterday's copy is restored, refreshed, and saved under the new day's key | Restore plus an incremental refresh |

Set `auto-update-db: 'false'` for air-gapped runs or when a cached database is
managed elsewhere; the scan then uses the cached data plus targeted advisory
lookups.
