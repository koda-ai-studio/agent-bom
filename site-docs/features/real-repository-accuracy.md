# Accuracy on real repositories

Dependency findings are only useful if they are right. Besides the
[range-matcher baseline](scanning.md), we scan public, real-world repositories at
pinned commits and compare every result with an independent ground truth.

## Method

- **Repositories**: seven public projects across five ecosystems, each at a fixed commit.
- **Ground truth**: packages parsed independently from each lockfile or manifest
  (Gradle and Maven checked by hand), then every `name@version` queried against
  [OSV](https://osv.dev) and matched through advisory aliases.
- **Scan**: `agent-bom scan` with a freshly synced local advisory database, one
  repository at a time. The offline run (`--offline`) was compared for Go.
- **Measured** on 2026-10-25 against the 0.111.0 code.

## Results

| Repository | Ecosystem | Packages found / expected | Advisories matched | Missed | False positives | Scan outcome |
|---|---|---|---|---|---|---|
| temporalio/temporal | Go modules | 214 / 214 | 11 | 0 | 0 | partial (unrelated source-analysis limit) |
| temporalio/sdk-typescript | npm (pnpm) | 2,068 / 2,068 | 180 | 0 | 0 | partial |
| temporalio/sdk-typescript | Cargo | 370 / 370 | 13 | 0 | 0 | partial |
| temporalio/sdk-python | PyPI (uv) | 235 / 235 | 40 | 0 | 0 | complete |
| temporalio/sdk-python | Cargo | 362 / 362 | 7 | 0 | 0 | complete |
| temporalio/sdk-java | Gradle | 30 / 43 declared | 27 | 0 | 0 | partial: no `gradle.lockfile` |
| snowflakedb/snowflake-connector-python | PyPI (`setup.cfg`) | 37 / 38 direct | 4 | 0 | 0 | partial: transitive dependencies not resolved |
| snowflakedb/snowflake-jdbc | Maven (with parent POM) | 89 / 89 | 24 | 0 | 0 | partial: BOM-imported versions unresolved |

**Across the seven repositories: 299 of 299 OSV advisories matched, with no false
positives.** Offline results on Go were identical to online results.

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
- NuGet, RubyGems and Composer were not part of this measurement.
- The Go toolchain's own standard library advisories are not reported.

Results will be re-measured each release.
