# Report And Stored-Result Volume

Evidence status: measured
Raw result artifact: `docs/perf/results/report-volume-2026-10-26.json`

## Claim

On the offline demo estate (51 findings, 15 blast-radius rows):

- A stored scan-job row shrinks from 947,615 to 77,175 bytes (12.3x) with the
  zstd result codec, at a similar encode and decode cost.
- The JSON report shrinks 5.4% (1,440,689 to 1,363,573 bytes) by referencing
  exposure paths from `blast_radius` instead of copying them; the
  `blast_radius` section itself shrinks 34% (215,385 to 141,347 bytes).
- `-o report.json.gz` writes 92,167 bytes, 14.8x smaller than the plain report.
- Writing the report holds 230 KB of Python allocations instead of 1.2 MB, and
  that peak stays flat as the report grows (24.0 MB before, 230 KB after on a
  20x tiled report), because each item of a top-level list is encoded
  separately.

## Scope

- `agent_bom.api.job_payload_codec` (SQLite and PostgreSQL job rows; see
  [`docs/STORAGE_BACKENDS.md`](../STORAGE_BACKENDS.md#compressed-scan-job-results))
- The JSON report's `blast_radius` rows (`schema_version: "2"`)
- `agent_bom.output.json_writer`, which also writes CycloneDX, SARIF and SPDX
  exports and `.gz` outputs

Excluded:

- Building the report dictionary itself (`to_json`) still happens in memory;
  the writer peak above is only the encoding step.
- Database I/O and network transfer. Row sizes are the serialized payload
  handed to the database, not on-disk page usage; PostgreSQL TOAST may
  compress the uncompressed baseline further.
- `findings[].controls` (about 16% of the demo report) and the top-level
  `packages` list, which repeats `ai_bom_entities.packages`, are unchanged.

## Environment

- macOS arm64 laptop, Python 3.13.5, shared with other jobs (load average
  8.7-10.1). Wall times are noisy; byte counts are exact and deterministic.
- "Before" is a `git archive` of `origin/main` at `e42d0d569`.

## Commands

```bash
git archive origin/main src | tar -x -C /tmp/base
uv run python scripts/bench/report_volume_bench.py --src /tmp/base/src            # before
uv run python scripts/bench/report_volume_bench.py --src src                      # after
uv run python scripts/bench/report_volume_bench.py --src src --repeat 20          # tiled
```

## Results

| Metric | Before | After |
|---|---|---|
| JSON report (indent 2) | 1,440,689 B | 1,363,573 B |
| JSON report, gzip level 6 | 103,608 B | 97,840 B |
| `blast_radius` section | 215,385 B | 141,347 B |
| Stored job row | 947,615 B | 77,175 B |
| Job row encode / decode | 6.0 / 10.9 ms | 11.8 / 10.1 ms |
| `write_json_file` traced peak | 1,213,308 B | 230,293 B |

Tiled 20x (1,020 findings, 300 blast-radius rows; synthetic):

| Metric | Before | After |
|---|---|---|
| JSON report | 22,632,225 B | 21,089,905 B |
| `write_json_file` traced peak | 24,044,300 B | 230,321 B |

The tiled job row (14.65 MB before, 94 KB after) is not a fair compression
figure: tiling repeats identical rows, which zstd folds away. Use the demo
row's 12.3x as the expected ratio.

## Known gaps

- A completed job's result is still decoded whole before
  `GET /v1/scan/{id}/result/{section}` slices it; the paged response is small
  but the server work scales with the result. Filtered findings at scale should
  use `GET /v1/findings`, which reads the normalized finding tables.
- No production-size estate was available; the 20x tiled run shows the writer's
  memory shape, not real-world compression ratios.
