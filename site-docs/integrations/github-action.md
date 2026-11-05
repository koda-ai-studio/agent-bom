# GitHub Action

`koda-ai-studio/agent-bom` runs agent-bom in a GitHub Actions job. It scans
the checkout (packages, MCP configs, Terraform, Kubernetes, Helm,
CloudFormation, workflows, skills and secrets), gates the build on findings,
and reports them as SARIF, a job summary, line annotations and an optional
pull request comment.

`@v0` follows the latest 0.x release. Pin a release tag (for example
`@v0.111.0`) or a commit SHA when you need the scanner version to stay fixed.

## Quick start

```yaml
- uses: actions/checkout@v4
- uses: koda-ai-studio/agent-bom@v0
```

With default inputs the Action:

- scans the checkout (`scan-type: scan`, `scan-ref: .`) and fails on high or
  critical findings (`severity-threshold: high`);
- ignores the runner's home-directory MCP configs, which are not part of your
  repository;
- writes `agent-bom-results.sarif`, a job summary with the top findings
  (severity, file:line, rule, fix), and line annotations
  (critical/high = error, medium = warning, low = notice; `max-annotations`
  caps them at 50 and reports how many more are in the SARIF file);
- posts a pull request comment when the token can (`pr-comment: auto`).

## Full pull request gate

```yaml
name: agent-bom
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  agent-bom:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload-sarif
      pull-requests: write     # pr-comment
    steps:
      - uses: actions/checkout@v4
      - uses: koda-ai-studio/agent-bom@v0
        with:
          severity-threshold: high
          upload-sarif: 'true'
          mcp-gate: 'true'
          sbom-artifact: cyclonedx
```

Keep the workflow default at `contents: read` and grant write scopes to the
one job that needs them. Without `security-events: write`, leave
`upload-sarif` off. Without `pull-requests: write` (for example on pull
requests from forks), `pr-comment: auto` skips the comment with a notice;
`pr-comment: 'true'` fails the step instead, and `'false'` never posts.

## Weekly rescan

New advisories are published against code that has not changed, so a pull
request gate alone misses them. Add a `schedule:` trigger to the same
workflow, or keep a separate one like this, to rescan the default branch
every week and refresh code scanning:

```yaml
name: agent-bom weekly
on:
  schedule:
    - cron: '17 6 * * 1'   # Mondays 06:17 UTC
  workflow_dispatch:
permissions:
  contents: read
jobs:
  agent-bom:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload-sarif
    steps:
      - uses: actions/checkout@v4
      - uses: koda-ai-studio/agent-bom@v0
        with:
          upload-sarif: 'true'
```

Scheduled runs have no pull request, so no comment is posted; results land in
code scanning and the job summary. A failing scheduled run means a high or
critical finding now exists on the default branch.

## New findings only

`baseline` takes a JSON report from the base branch and runs
`scan --baseline <file> --delta`: the report, SARIF, summary and every gate
cover only findings that are new. This works for every finding type (CVEs,
IaC, workflow, skill, secret and posture findings). Non-CVE findings are
matched by type, file, rule and message with line numbers and the checkout
folder name ignored, so moving code or scanning from a differently named folder
does not reopen them.

```yaml
name: agent-bom new findings
on: pull_request
permissions:
  contents: read
jobs:
  agent-bom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: base
      - uses: actions/checkout@v4
        with:
          path: head
      - name: Baseline from the base branch
        uses: koda-ai-studio/agent-bom@v0
        with:
          scan-ref: base
          format: json
          output: baseline.json
          severity-threshold: ''
          annotations: 'false'
          pr-comment: 'false'
      - name: Gate on new findings
        uses: koda-ai-studio/agent-bom@v0
        with:
          scan-ref: head
          baseline: baseline.json
```

Both checkouts sit in their own directory so neither scan includes the other.
`baseline` applies to `scan-type: scan`; other scan types fail with an error
rather than gate on every finding.

`severity-threshold: ''` makes the baseline step report-only:

- Severity findings do not fail the step; `exit-code` still reports what the
  scanner returned, and `scan-status` is `violations`.
- A partial scan does not fail it either, because the gate step still needs its
  report. It emits a warning, `scan-status` is `partial`, and the summary says the
  results are incomplete. Findings a partial baseline missed read as new, so the
  gate errs towards failing.
- A known-malicious package, a failed or unreadable scan, and an explicit `policy`
  or `fail-on-kev` gate still fail the step.

The gate step keeps the default threshold and fails closed, including on a partial
scan of the head checkout. A report from before the folder-independent matching
still matches. A report with no `findings` list suppresses nothing, so every
non-CVE finding reads as new rather than clean.

Uploading the gate's SARIF from this layout would show `head/...` paths, because
GitHub resolves them from the repository root. Keep `upload-sarif` on a separate
scan of a normal checkout, as in the full pull request gate above.

## MCP gate

`mcp-gate: 'true'` runs on `pull_request` events. It diffs the `.mcp.json`
and `mcp.json` files the pull request changes, collects the servers it adds
or redefines, and fails when one of them:

- is blocked by the launcher check (a command that is not a recognised MCP
  launcher, such as `bash -c "curl … | bash"`);
- ships a known-malicious package; or
- reaches a vulnerability at or above `severity-threshold`.

Servers the pull request does not touch never fail the gate.

## SBOM artifact

`sbom-artifact: cyclonedx` (or `spdx`) re-runs the same scope offline, writes
`agent-bom-sbom.cdx.json` (or `agent-bom-sbom.spdx.json`), exposes it as the
`sbom-file` output and uploads it as the `agent-bom-sbom` workflow artifact.
It is available for `scan-type` `scan`, `image`, `fs` and `sbom`. The
separate `sbom` input still takes an existing SBOM to ingest.

## Scan types

| `scan-type` | Command | Notes |
|---|---|---|
| `scan` (default) | `agent-bom scan <scan-ref>` | Full project scan. With only `sbom`/`image` set and no `scan-ref`, scans just that artifact. |
| `image` | `agent-bom image <ref>` | `scan-ref` or `image` is the image reference. |
| `fs` | `agent-bom fs <path>` | Mounted filesystem or directory. |
| `sbom` | `agent-bom sbom <file>` | Existing CycloneDX or SPDX file. |
| `iac` | `agent-bom iac <paths>` | Comma-separated paths. |
| `secrets`, `code` | `agent-bom secrets <path>` or `agent-bom code <path>` | JSON output only; `upload-sarif` is rejected. |
| `skills` | `agent-bom skills scan <path>` | Uses the `*-verdict` and `skills-ci` gates. |

The Action only passes flags the selected command accepts. A blocking gate or
scan target that a command cannot honour (for example `fail-on-kev` or
`baseline` with `scan-type: iac`) fails the step with an error; other
unsupported inputs are dropped with a warning.

## Vulnerability database scope

`vuln-db-scope: application` (the default) keeps the application-ecosystem OSV
archives locally. Packages in any other ecosystem, such as OS packages from an
image, are answered by live OSV (`api.osv.dev`), and a scan where neither could
answer stays incomplete rather than clean. The first refresh also caps NVD at 60
seconds, newest CVEs first: the report and the log say `NVD sync partial
(time_budget)`, and the next refresh resumes it. Set
`AGENT_BOM_NVD_TIME_BUDGET_SECONDS` to choose another budget.

`vuln-db-scope: full` reads the all-ecosystems archive (about 2.9 GB). Use it when
OS packages must be answered from local data, including in the offline
`sbom-artifact` step. The two scopes cache separately.

## Vulnerability database cache

With `auto-update-db: 'true'` (the default) the scan refreshes the local
vulnerability database at `~/.agent-bom/db/vulns.db` when it misses the daily
freshness target. The Action caches that file under a key with one bucket per
UTC day and restores the newest earlier copy through `restore-keys`:

| Run | What happens | Cost |
|---|---|---|
| Cold (no cache entry yet) | The scoped database is built, then the cache is saved | Minutes: about 5 minutes and a 270 MB database on a developer laptop; runner time varies with network and sources. `vuln-db-scope: full` measured 21 to 23 minutes on Linux and macOS runners and 72 minutes on Windows before the first-build write path was reduced |
| Warm, same day | The day's cache entry is restored; no sync | Cache restore only (proportional to database size) |
| Warm, first run of a new day | Yesterday's copy is restored, refreshed, and saved under the new day's key | Restore plus an incremental refresh |

Set `auto-update-db: 'false'` for air-gapped runs or when a cached database is
managed elsewhere; the scan then uses the cached data plus targeted advisory
lookups.

The refresh uses the default `agent-bom db update` sources (OSV, Alpine,
Debian, EPSS, KEV and NVD), so CVEs that only NVD carries, with their CPE
version ranges, reach the cached database. Without a key NVD is read keyless
(a 14-day window at a lower rate limit). To widen it to 120 days, store an
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) as a
repository or environment secret and pass it in:

```yaml
- uses: actions/checkout@v4
- uses: koda-ai-studio/agent-bom@v0
  with:
    nvd-api-key: ${{ secrets.NVD_API_KEY }}
```

The Action sets it only as the `NVD_API_KEY` environment variable of the scan
step (a job-level `NVD_API_KEY` works too); it is never written into a script
or printed, and agent-bom sends it only to the NVD API in a request header
(see [PERMISSIONS.md](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/PERMISSIONS.md)).
Secrets are not available to pull requests from forks, so those runs read NVD
keyless.

## Possibly affected distro packages

Distributions backport fixes without changing the upstream version, so a
distro package of a CPE product (for example Debian `php8.2-cli` for
`php:php`) cannot be judged from upstream NVD ranges. When the local database
has no distro record for it, the scan reports it as possibly affected: the
SARIF result has level `note` and `properties.verdict: possibly_affected`, it
shows in code scanning, as a `notice` annotation and in a separate
"Possibly affected" line of the job summary and pull request comment.

These results are not counted as findings: they are left out of
`vulnerability-count`, the summary's severity totals, the badge and the
posture grade, and they do not fail `severity-threshold` or any other gate.
Verify each one against the distribution's security advisory. The
[new CVE runbook](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/RESPOND_TO_A_NEW_CVE.md)
walks through the whole flow.

## Other CI systems

- Reusable workflow: call
  `koda-ai-studio/agent-bom/.github/workflows/agent-bom-reusable.yml@v0`
  from a job with `uses:` (see the header of
  [the workflow](https://github.com/koda-ai-studio/agent-bom/blob/main/.github/workflows/agent-bom-reusable.yml)).
- [GitLab CI](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/gitlab-ci.yml)
- [Azure Pipelines](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/azure-pipelines.yml)
- [Bitbucket Pipelines](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/bitbucket-pipelines.yml)

Every SARIF result carries the physical location GitHub requires. A finding
with no repository file (a package from an image or a self-scan, for example) uses
a marked `agent-bom-findings/...` path that is not a real file, with
`properties.no_source_file: true` and its identity in `logicalLocations`.

For SARIF upload problems see
[GitHub Action SARIF troubleshooting](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/GITHUB_ACTION_SARIF_TROUBLESHOOTING.md),
and for exit codes and outputs see [exit codes](../reference/exit-codes.md).
