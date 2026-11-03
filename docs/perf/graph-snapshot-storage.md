# Retained graph storage: measurements and migration design

Run an isolated synthetic SQLite storage profile:

```bash
uv run python scripts/profile_graph_snapshot_storage.py --output /tmp/graph-storage-10 --snapshots 10 --nodes 1000
uv run python scripts/profile_graph_snapshot_storage.py --output /tmp/graph-storage-100 --snapshots 100 --nodes 1000
```

Each output must be a new directory. The artifact contains the original
database, a complete backup, a restored copy, and `receipt.json`. It uses no
network connection or existing database. The next step is to compare the
receipt's object sizes, full-export hashes and timing conditions against the
deployment's workload before proposing a migration.

The fixture retains 1,000 nodes and 999 directed edges per snapshot. Ten percent
of node attributes change each time; identity and topology stay stable. A
second tenant uses identical node IDs. Export hashes must match after restore,
and retained exports must remain identical after a tenant-scoped purge and
vacuum. The original history and archive remain intact. The simulated purge
advances the clock on the restored copy while keeping a 180-day interval.

## Local baseline

The November 2026 sample used an Apple M4 with 16 GiB RAM, macOS arm64, Python
3.13.5 and SQLite 3.50.2. These are single local synthetic runs, with warm OS
file caches, not production capacity measurements or tail-latency guarantees.

| SQLite measurement | 10 snapshots | 100 snapshots |
|---|---:|---:|
| Retained database before the additional tenant | 29,822,976 bytes | 297,578,496 bytes |
| Backup | 0.084 s | 0.750 s |
| Restore | 0.075 s | 0.777 s |
| Purge half of the primary tenant's snapshots | 0.215 s | 4.616 s |
| Vacuum restored copy | 0.129 s | 1.107 s |
| File after purge, including additional tenant | 32,825,344 bytes | 300,654,592 bytes |
| File after vacuum, including additional tenant | 18,407,424 bytes | 156,905,472 bytes |

One full JSON graph export was 2,040,934 bytes; gzip reduced this fixture to
80,901 bytes. Compression benefits depend on actual evidence entropy. At 100
snapshots, stored attribute bytes were 71,618,000 versus 8,446,100 for distinct
tenant-scoped attribute payloads. This is an upper-bound opportunity estimate:
it excludes new references, indexes, payload metadata and read costs. It is
not the expected reduction of the whole database.

A separate disposable, fully migrated Postgres 16 run used the restricted
application role for graph writes and reads. Ten/100 snapshots retained
46,080,000/369,025,024 bytes across graph tables and their indexes; indexes
accounted for 24,182,784/151,625,728 bytes. Full custom-format archives, excluding
tenant-binding keys, were 1,235,284/8,100,905 bytes. Restore into a separate
database took 1.786/14.046 seconds and reproduced every stored graph-row hash.
Purge of half the snapshots took 0.106/1.157 seconds; ordinary vacuum took
0.300/1.452 seconds and did not materially shrink allocated files. Foreign
tenant reads were denied by RLS. Administrator access was used only for
disposable database creation, measurement and backup/restore, not application
read qualification.

The real Postgres contract is included in CI:
`tests/test_graph_retention_live_postgres.py`. It checks the post-commit tenant
rebind, cursor-based batch execution, preservation of invalid timestamps,
child-row cleanup and isolation of another tenant's expired history. The
existing restore qualification also checks the operator's independently
restored binding authority: `tests/test_postgres_backup_restore.py`.

## Selected design, not a deployed migration

Prioritize immutable payload deduplication while keeping observation membership
and lifecycle fields per snapshot. Payload keys must include tenant, schema
version and a digest of exact canonical bytes; verify bytes on a digest match.
Never share secret-bearing payloads across tenants. Node identities, edge
direction, evidence receipts and full exports must remain unchanged. Search
indexes need separate measurements: payload deduplication alone does not remove
the substantial per-snapshot index cost shown above.

Time partitioning can reduce large historical purge work, but it is not the
first migration selected by these measurements. Per-tenant retention overrides
prevent dropping a shared time partition until every contained tenant permits
expiry. A partition key would also change uniqueness and foreign-key design.
The current runs establish neither a 10,000-push/day failure threshold nor a
production partition size.

Implement the chosen design behind these gates:

1. Add payload and membership tables with the existing tenant RLS policies.
   Dual-write new snapshots without changing old readers. Backfill in bounded,
   resumable batches with a high-water receipt; do not rewrite source evidence.
2. Compare every node, edge, finding link and export hash on SQLite and
   Postgres. Exercise missing payloads, hash collisions, interrupted backfills,
   concurrent ingest, exact tenant isolation and historical pagination.
3. Switch reads only after parity. Retain original rows during the rollback
   window. Rollback selects the old reader and resumes from preserved source
   snapshots; no destructive downgrade is required.
4. Make garbage collection reference-safe: delete a payload only after all
   retained memberships expire. Use tenant-scoped locks, bounded batches,
   tombstones and durable receipts. Interruption must leave either complete
   readable history or an explicit pending cleanup state.
5. Qualify backup/restore with payloads, references, checkpoints and separately
   provisioned binding keys. Restore must prove full historical parity and RLS
   before traffic resumes.

The current cursor batch limit bounds parameter buffering, not total purge
transaction time. Large-snapshot cleanup still needs resumable deletion and
retention receipts before a bounded production purge claim. No retention
interval, historical schema or customer data is changed by this design.
