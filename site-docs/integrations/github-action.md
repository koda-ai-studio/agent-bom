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

## New findings only

`baseline` takes a JSON report from the base branch and runs
`scan --baseline <file> --delta`: the report, SARIF, summary and every gate
cover only findings that are new. This works for every finding type (CVEs,
IaC, workflow, skill, secret and posture findings). Non-CVE findings are
matched by type, file, rule and message with line numbers ignored, so moving
code does not reopen them.

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

## Other CI systems

- Reusable workflow: call
  `koda-ai-studio/agent-bom/.github/workflows/agent-bom-reusable.yml@v0`
  from a job with `uses:` (see the header of
  [the workflow](https://github.com/koda-ai-studio/agent-bom/blob/main/.github/workflows/agent-bom-reusable.yml)).
- [GitLab CI](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/gitlab-ci.yml)
- [Azure Pipelines](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/azure-pipelines.yml)
- [Bitbucket Pipelines](https://github.com/koda-ai-studio/agent-bom/blob/main/examples/ci/bitbucket-pipelines.yml)

For SARIF upload problems see
[GitHub Action SARIF troubleshooting](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/GITHUB_ACTION_SARIF_TROUBLESHOOTING.md),
and for exit codes and outputs see [exit codes](../reference/exit-codes.md).
