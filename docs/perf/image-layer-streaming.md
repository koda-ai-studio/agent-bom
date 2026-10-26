# Image Layer Streaming Evidence

Evidence status: measured
Owner issue: #5991
Raw result artifact: `docs/perf/results/image-layer-streaming-2026-10-25.json`

## Claim

Peak memory of the native image parser (`agent_bom.oci_parser.scan_oci`) does
not grow with layer size. On synthetic `docker save` images of 256 MiB and
1 GiB, both plain and gzip-wrapped, the Python allocation peak stays between
8.5 and 8.8 MiB and the process max RSS stays between 86 and 111 MiB. Before
layer streaming, the same images peaked at 2.3 to 3.1 GiB of Python
allocations.

## Scope

- Layer extraction in `scan_oci` for `docker save` tarballs, which shares one
  layer walk with OCI layout directories
- Uncompressed layers read in place, and gzip layers inflated in 1 MiB chunks
  into a temporary file
- dpkg package database extraction (2,000 packages)

Excluded from this measured run:

- Vulnerability matching, enrichment and report rendering. The end-to-end
  `agent-bom image` profile, including kernel-header CVE fan-out, is still
  open under #5991.
- Image pulls (`docker save`) and registry I/O
- Layers with very large file counts. The `AGENT_BOM_OCI_MAX_LAYER_MEMBERS`
  limit bounds these but is not benchmarked here.

## Environment

- macOS arm64 laptop, Python 3.13.5, shared with other jobs. The load average
  is recorded in the raw artifact. Wall time is noisy; memory figures are the
  primary metric.
- Each image has two layers: an uncompressed layer holding a dpkg status file
  plus an incompressible filler file, and a gzip layer holding the same
  filler. The filler size is the "layer MiB" column below.

## Commands

```bash
# after (this tree)
uv run python scripts/bench/image_layer_bench.py --sizes 128,512 --gzip-outer
# before (a baseline source tree, e.g. `git archive f2bccb461 src | tar -x -C /tmp/base`)
uv run python scripts/bench/image_layer_bench.py --sizes 128,512 --gzip-outer --src /tmp/base/src
```

## Results

| Layer MiB | Image | Before peak (traced) | After peak (traced) | Before max RSS | After max RSS | Before wall | After wall |
|---|---|---|---|---|---|---|---|
| 128 | 256 MiB tar | 2,309.5 MiB | 8.5 MiB | 454.8 MiB | 98.7 MiB | 0.93 s | 0.57 s |
| 128 | 256 MiB tar.gz | 2,325.8 MiB | 8.7 MiB | 457.3 MiB | 85.8 MiB | 2.72 s | 2.21 s |
| 512 | 1 GiB tar | 3,077.6 MiB | 8.6 MiB | 673.2 MiB | 102.2 MiB | 6.06 s | 1.25 s |
| 512 | 1 GiB tar.gz | 3,093.9 MiB | 8.8 MiB | 717.1 MiB | 110.7 MiB | 7.73 s | 2.97 s |

The traced peak before the change was above the image size because each layer
was read with `read(2 GiB + 1)`, which preallocates the full cap. Max RSS was
lower than the traced peak because the untouched pages of that buffer were
never committed. The regression tests in `tests/test_oci_bounded_scan.py`
assert a peak below 12 MiB for 24 MiB layers on every layer path.

## Gaps

- The end-to-end `agent-bom image` profile (matching, kernel-package CVE
  fan-out, report build) and the 40k-package manifest benchmark from #5991 are
  not covered here.
- These results come from one laptop run, not from a CI runner.
