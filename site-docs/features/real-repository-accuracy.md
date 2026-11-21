# Accuracy on real repositories

Dependency findings are only useful if they are right. Besides the
[range-matcher baseline](scanning.md), we scan public, real-world repositories at
pinned commits and compare every result with an independent ground truth. The
measurement is scripted, so anyone can repeat it.

## Method

- **Repositories**: six public projects at the commits listed below, recorded in
  [`docs/accuracy/real-repos.json`](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/accuracy/real-repos.json).
- **Scan**: `agent-bom scan <checkout> -f json -o <report>` against a freshly
  synced local OSV advisory database, one repository at a time, with an isolated
  home and state directory.
- **Ground truth**: each lockfile is parsed by small parsers written for this
  measurement, separate from agent-bom's own (`go.mod`, `pnpm-lock.yaml`,
  `Cargo.lock`, `uv.lock`). Every registry `name@version` is queried at the
  [OSV API](https://osv.dev), and each advisory is fetched for its aliases.
- **Matching**: advisory identity comes only from OSV aliases (GHSA, CVE, PYSEC,
  GO and RUSTSEC IDs joined transitively), so one advisory with several IDs
  counts once, and agent-bom's own alias data cannot turn a miss into a match.
- **Differences**: every miss and every extra finding is classified. Withdrawn
  advisories and advisories published or changed after the database sync are
  listed as data-timing differences, not as errors. Anything else is reported as
  unexplained.
- **Not independently verified**: Gradle builds without `gradle.lockfile`,
  `setup.cfg` ranges and Maven BOM imports have no resolved versions without
  running the build. For those, the scan's own numbers are shown, but they are
  left out of the headline figure.

## Results

Measured on 2026-11-21 (UTC) against agent-bom 0.115.4, with the OSV database
synced at 02:25 UTC the same day. Full output:
[`docs/accuracy/real-repos-results.json`](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/accuracy/real-repos-results.json).

### Independently verified lockfiles

| Repository @ commit | Ecosystem (lockfiles) | Packages found / expected | Advisories matched / expected | Missed | Extra | Scan outcome |
|---|---|---|---|---|---|---|
| temporalio/temporal @ `32ef011fbd1e` | Go (3 `go.mod`) | 217 / 217 | 2 / 2 | 0 | 0 | partial: one generated Go file exceeds the source-analysis size limit |
| temporalio/sdk-typescript @ `f5107ac96256` | npm (2 `pnpm-lock.yaml`) | 2,253 / 2,253 | 67 / 67 | 0 | 0 | partial: one TypeScript file fell back to regex source analysis; some local advisories carried a stale alias group and were matched by their own IDs only |
| temporalio/sdk-typescript @ `f5107ac96256` | Cargo (`Cargo.lock`) | 395 / 395 | 9 / 9 | 0 | 0 | (same scan) |
| temporalio/sdk-python @ `5c925a41b36b` | PyPI (`uv.lock`) | 228 / 228 | 36 / 36 | 0 | 0 | complete |
| temporalio/sdk-python @ `5c925a41b36b` | Cargo (`Cargo.lock`) | 364 / 364 | 1 / 1 | 0 | 0 | (same scan) |

**Across the verified lockfiles: 3,457 of 3,457 packages found and 115 of 115 OSV
advisories matched, with no misses and no extra findings.** "Partial" in these
rows comes from source-code analysis limits and, for sdk-typescript, an alias
warning from the advisory data; neither left a locked package or an OSV advisory
unreported. Workspace, path and git-sourced packages (17 crates, 2 local Go
replacements and the project's own Python package) are not registry packages and
are excluded from both sides.

### Not independently verified

| Repository @ commit | Manifests | Packages found | Advisory findings | Possibly affected | Why there is no ground truth |
|---|---|---|---|---|---|
| temporalio/sdk-java @ `f5c8e4e1c135` | Gradle (`build.gradle`, no lockfile) | 47 | 28 | 0 | Resolved and transitive versions exist only after running Gradle; the scan reports `partial` and names each build file. |
| snowflakedb/snowflake-connector-python @ `0397b47a9004` | `setup.cfg` ranges | 95 | 0 | 5 | Ranges, not versions; the scan picks the version a fresh install would get and reports `partial`. |
| snowflakedb/snowflake-jdbc @ `ee32e7dfec6e` | Maven (parent POM, BOM imports) | 87 | 24 | 0 | Managed versions are resolved only by Maven; the scan reports `partial`. |

These numbers say what the scan reported, not whether it was right. "Possibly
affected" advisories match a version chosen from a declared range rather than a
locked one; agent-bom lists them separately from findings until the dependency
is locked or pinned.

Full commits:

| Repository | Commit |
|---|---|
| temporalio/temporal | `32ef011fbd1e38ecddf656fc3f5026f6641cfeab` |
| temporalio/sdk-typescript | `f5107ac96256c217cccf98cff278175bfa35b21e` |
| temporalio/sdk-python | `5c925a41b36b34d9ce32d03f1d1f07faa35b348a` |
| temporalio/sdk-java | `f5c8e4e1c135de05eacf014fd49a612c50f93b9e` |
| snowflakedb/snowflake-connector-python | `0397b47a90044a697810c58804b1f0b691244165` |
| snowflakedb/snowflake-jdbc | `ee32e7dfec6ebdd3c1bb954a66205255ffadb0ae` |

## What this does and does not show

- It shows that, for these lockfiles, agent-bom found every locked registry
  package and reported exactly the advisories OSV lists for those versions.
- The scan and the ground truth both use OSV advisory data. The measurement checks
  lockfile parsing, version matching and alias handling; it does not measure how
  complete OSV itself is.
- Six repositories and four lockfile formats are a small sample. NuGet,
  RubyGems, Composer, npm `package-lock.json`, Yarn, Poetry and `go.sum`-only
  projects were not part of this measurement.
- An earlier, unscripted measurement (2026-10-25, agent-bom 0.111.0, commits not
  recorded) also counted the Gradle, `setup.cfg` and Maven projects, checked by
  hand. Those cannot be repeated from a recorded ground truth, so they are no
  longer part of the headline number.
- Advisory counts move as repositories update dependencies and as OSV adds
  advisories; re-run the script rather than reusing these numbers for a later date.

## What "partial" means

When a version cannot be resolved without running the build, agent-bom reports the
scan as `partial` and names the manifest, instead of returning a clean result it
cannot prove. That happens for Gradle builds without a lockfile, Maven BOM imports,
`setup.py` files that compute their dependencies, and manifests whose transitive
dependencies are not locked. Add a lockfile to get a complete answer.

## Limits

- Gradle without `gradle.lockfile` covers declared dependencies only; transitive
  dependencies need a lockfile.
- Dynamic `setup.py` and unlocked Python manifests cover direct dependencies only.
- The Go toolchain's own standard library advisories are not reported.

## Reproduce

From a checkout of this repository with agent-bom installed in the active
Python environment (for example `uv sync`):

```bash
python scripts/measure_real_repo_accuracy.py --sync-db
```

The script downloads each repository's source archive at the pinned commit,
syncs the OSV database for PyPI, npm, Go, Maven and crates.io into a temporary
state directory (your `~/.agent-bom` is not read or changed), scans, queries the
OSV API, and writes `docs/accuracy/real-repos-results.json`. Use `--repo
temporalio/sdk-python` to measure one repository, `--work-dir` to choose where
the checkouts, scan reports and database go (a later run reuses them), and
`--python` to point at another agent-bom installation. It needs network access
to GitHub and OSV; the full run took about 10 minutes on a laptop.

To check a repository of your own, add it to `docs/accuracy/real-repos.json`
with its commit and lockfile paths. In the results, read each repository's
`scan.issues` and `coverage_warnings` before counting a miss: a `partial` scan
names the manifest it could not resolve.
