# Image Scan End-to-End Evidence

Evidence status: measured
Owner issue: #5991
Raw result artifact: `docs/perf/results/image-scan-end-to-end-2026-10-26.json`

## Claim

`agent-bom image php:8.3.30-cli` (172 packages, 4,424 findings offline, of
which 3,513 are `linux-libc-dev` kernel CVEs) now peaks at 413 MiB of memory
for console output and 758 MiB for JSON output, down from about 2.5 GiB on
`main` for both, and uses 42 s instead of 71 s of CPU for console output and
52 s instead of 277 s for JSON output, with the identical set of (CVE,
package, version) findings. A 40,000-package offline manifest scan peaks at
684 MiB (main: 1,413 MiB).

Package extraction and vulnerability matching were never the bottleneck: on
`main` they took about 12 s of the run. The time and memory went to building
and redacting per-finding report data.

## Scope

- `agent-bom image` on the `php:8.3.30-cli` image, from a `docker save`
  tarball (`--tar … --offline`, local vulnerability DB) and end to end from the
  Docker daemon (online OSV lookups)
- Console and JSON output
- A 40,000-package npm lockfile scanned offline against a seeded local DB
  (`tests/test_scan_scale_contract.py`)

Excluded:

- SARIF and CycloneDX export time at this size (the full php export parity
  check exercises them; see Gaps)
- Image pull time; the image was already in the local Docker store

## Environment

- macOS arm64 workstation (16 GB), Python 3.13.5, Docker 29.8.0. The machine
  was shared with other jobs; the 1-minute load average at the start of every
  run is in the raw artifact and was between 13 and 34. Wall times are not
  comparable across runs, so CPU time (user + sys) and the peak memory
  footprint (`/usr/bin/time -l`) are the primary result. Max RSS is also in the
  artifact but undercounts under memory pressure.
- Before: `origin/main` at `e42d0d569`, run from a `git archive` copy of `src`
  on the same virtualenv. After: this change.
- Local vulnerability DB last synced 2026-08-19 (offline runs). A profile
  file was disabled with `AGENT_BOM_CONFIG` so `--format console` was honoured.

## Commands

```bash
docker save php:8.3.30-cli -o php.tar
export AGENT_BOM_CONFIG=/nonexistent/config.toml

# after (this tree)
/usr/bin/time -l uv run agent-bom image --tar php.tar --offline --format console
/usr/bin/time -l uv run agent-bom image --tar php.tar --offline --format json --output after.json
/usr/bin/time -l uv run agent-bom image php:8.3.30-cli --format console

# before: the same commands with a baseline source tree first on the path
git archive -o main-src.tar e42d0d569 src && mkdir base && tar -xf main-src.tar -C base
PYTHONPATH=base/src /usr/bin/time -l uv run python -m agent_bom image --tar php.tar --offline --format json --output before.json

# finding-set parity between the two JSON reports
python - before.json after.json <<'EOF'
import json, sys
def triples(path):
    doc = json.load(open(path))
    return {(f["cve_id"], f["evidence"]["package_name"], f["evidence"]["package_version"])
            for f in doc["findings"] if f["finding_type"] == "CVE"}
before, after = (triples(p) for p in sys.argv[1:3])
print(len(before), len(after), before == after)
EOF

# 40,000-package offline manifest (post-merge CI lane)
uv run pytest tests/test_scan_scale_contract.py -m scan_performance -p no:randomly
```

Profiles were taken with `python -m cProfile -m agent_bom image …`.

## Results

`php:8.3.30-cli`, 4,424 findings in every offline run:

| Run | Before wall | After wall | Before CPU | After CPU | Before peak footprint | After peak footprint |
|---|---|---|---|---|---|---|
| Offline `--tar`, console | 95.6 s | 163.0 s ¹ | 70.7 s | 41.8 s | 2,510 MiB | 413 MiB |
| Offline `--tar`, JSON | 545.0 s | 248.0 s ¹ | 276.8 s | 52.0 s | 2,516 MiB | 758 MiB |
| Online from the daemon, console (4,506 findings) | 386.1 s | — ² | 105.6 s | 45.1 s | 2,535 MiB | 352 MiB |

¹ Contended machine; in quieter runs earlier the same day the branch took
28.5 s (console) and 46.0 s (JSON) of wall time.
² The run was suspended part-way when all jobs on the machine were paused; its
wall time is not meaningful. CPU time and memory are unaffected.

40,000-package npm lockfile, offline, seeded local DB (200 advisories), JSON:

| | Wall | Peak RSS | CVE findings |
|---|---|---|---|
| Before | 251.3 s | 1,413 MiB | 200 |
| After | 130.4 s | 684 MiB | 200 |
| CI budget | 300 s | 1,000 MiB | exactly 200 |

Finding-set parity: the before and after offline JSON reports contain the
same 4,424 (CVE, package, version) triples, and the same summary counts (344
critical, 1,786 high). `tests/test_image_reference_cve_parity.py` freezes that
set and the alpine 3.14.2 reference set and checks JSON, SARIF, CycloneDX and
the console against them.

Where the time went on `main`, and the fix for each:

| Hotspot (cProfile, php image) | Cause | Fix |
|---|---|---|
| Redacting the JSON report: 223 s of 402 s | The per-package `ai_risk_context` was extended in place for every CVE, so the Nth `linux-libc-dev` CVE carried N attack summaries, up to 569 KB of text each (about 0.9 GB in total), and every credential pattern scanned all of it | Each CVE gets the package context plus its own summary only |
| `blast_radius_to_finding`: 57 s | The same package, layer and provenance strings were redacted again for each of 4,424 findings, twice per scan (776k `sanitize_text` calls) | A scan-scoped redaction memo, bounded at 8M input characters and cleared at scan end |
| Inventory snapshot at 40k packages: 21.6 s | Membership test on a per-server list of package ids | Ordered id sets (8.7 s); the same pattern fixed in both graph stores' compliance stats |
| Typosquat check at 40k packages: 14.8 s | Every package compared with every popular name, popular set re-sorted per call | Length index within the two-edit window, set order kept for ties (5.2 s) |

The console output now groups the kernel-header CVEs:

```text
  Kernel-header group linux-libc-dev@6.12.74-2 (debian 13) · 3513 CVEs: 297 critical · 1495 high · 1718 medium · 3 low
    3 KEV (CVE-2026-31431, CVE-2026-53266, CVE-2026-53362) · 297 critical (…) shown as rows · 3213 collapsed — -f json, sarif or cyclonedx lists every CVE
```

## Gaps

- One workstation under shared load, not a CI runner. The 40,000-package
  check runs after every merge in the `output-scale-performance` job.
- Remaining per-finding cost at 40,000 packages is package provenance built
  about ten times per package and `Package.stable_id` re-parsing the purl on
  every access. Both need a cache that is invalidated when a package is
  mutated, and are not changed here.
- SARIF export of the 4,424 php findings takes about 13 s on this machine; it
  was not profiled.
- Online (OSV) runs vary with OSV responses: the finding count differs from the
  offline set, and transient lookup errors were reported in some runs.
