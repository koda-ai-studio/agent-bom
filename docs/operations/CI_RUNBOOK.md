# CI Runbook

Operational guidance for the agent-bom CI pipeline. Use this when a PR is
stuck, a workflow fails unexpectedly, or you need to retrigger checks.

---

## CI lanes

PR CI tests GitHub's merge result with the **affected tests** and shared
contract smoke, partitioned across 1–12 `Python affected tests (shard N/total)`
jobs with a 15-minute bound. The classifier sizes the matrix from the full
affected selection plus mandatory smoke, targeting 900 worker-seconds per
runner using `tests/.ci-durations.json`. Missing timing data uses the maximum
fan-out; unknown modules use the measured seconds-per-byte estimate. No tests
are dropped to meet the budget. A slow indivisible module or stale timing can
still exceed the bound; the timeout remains a failure. Missing classifier
output falls back to twelve shards. A pull request never runs the full suite.
`scripts/pytest_ci_affected.py` selects:

- the changed-domain map from `scripts/pytest_ci_plan.py targeted`;
- every test module that directly imports, loads or names a changed source or
  script module (package `__init__.py` included, deleted modules included);
- every module below a changed `conftest.py`, the importers of a changed test
  helper, and the tests that reference a changed fixture file or fixture
  directory.

Shared or unmapped inputs (`full_python=true` from
`scripts/classify_ci_changes.py`) used to select the full suite; they now run
the affected selection plus smoke, and the full suite proves them after merge.
Only direct references count: a transitive or dependency-version regression
can pass the PR and fail the post-merge run, which then freezes merges (see
below). The job log prints the 50 slowest tests (`--durations=50`).

Full correctness is split into 4 parallel shards on Python 3.13 only for a
merge group (not enabled, see "Merge-queue configuration"); those shards run
every test module (with the same `otel` extra) plus the graph-fixture and DCM
guards on shard 0. `tests/test_ci_pr_fast_path.py` fails if any classifier
outcome lets a `pull_request` event start the full shards, the four-version
matrix, the full musl suite or every browser shard.

Postgres runs for its writer/migration inputs, shared model, API, storage,
authorization and dependency changes. UI browser checks build the standalone
app; the additional Docker build runs only for container, dependency or build
configuration changes on PRs. Main and nightly runs retain the full four-version
suite, coverage floor, Postgres, container, deployment and performance checks.
This is selective PR regression coverage, not a claim that every PR runs every
test. Main runs still exceed twenty minutes; that is the post-merge budget.

All lanes live in `ci.yml` unless noted. Python correctness jobs have a
45-minute safety bound; it is not a target duration. A timeout remains a failed
gate until a successful replacement run completes; passing sibling jobs does
not establish a green main commit.

Main, nightly and manual runs assign every test module to one of four shards
for each supported interpreter, using the same exhaustive plan as PRs.
`scripts/ci_pytest_workers.py` sizes pytest-xdist workers per job: every core
of the 4-vCPU, 16 GB hosted runner, capped at three when the selection holds
`tests/test_demo_estate_bootstrap.py` (each demo-estate worker reaches about
4 GB RSS). This divides work across runners; elapsed time
still depends on queue capacity and the slowest shard.

The planner balances measured per-module seconds from `tests/.ci-durations.json`
(longest module first, onto the least-loaded shard); modules without a
measurement are estimated from their size at the measured seconds per byte.
Refresh the file when shards drift apart, from the four `Full correctness
(Python 3.13, shard N)` job logs of one main run (their `-v` output carries
per-line timestamps):

```bash
for job in JOB_ID_0 JOB_ID_1 JOB_ID_2 JOB_ID_3; do
  gh api --allow-escape-sequences repos/OWNER/REPO/actions/jobs/$job/logs > "/tmp/shard-$job.log"
done
uv run python scripts/refresh_ci_durations.py --log /tmp/shard-*.log
```

Without CI logs, run the suite locally with `--junitxml=/tmp/junit.xml` and pass
`--junit /tmp/junit.xml` instead. Tests that only read the seeded demo estate
use `shared_demo_estate_client` (one seed per module); tests that write,
reseed or patch keep the per-test `demo_estate_client`. See
`tests/_demo_estate_fixtures.py`.

Python 3.11 shards upload coverage only after their tests pass. The combined
coverage job requires all four shards and enforces the repository-wide 75%
floor. Artifact names include the shard and run attempt, so failed-job retries
retain successful sibling evidence and preserve earlier artifacts. The combiner
selects the latest successful artifact for each shard from this workflow run;
missing, empty, corrupt or unmeasured data fails closed.

To reproduce the coverage gate after downloading this run's artifacts into
`coverage-artifacts/` with their artifact-name directories intact:

```bash
uv run python scripts/combine_ci_coverage.py coverage-artifacts --shards 4 --attempt 1
```

Use the actual run attempt. The command retains the shard databases, writes the
combined `.coverage` file and reports the coverage verdict. Investigate failed
tests or missing artifacts before rerunning only failed jobs; a partial report
cannot satisfy the release gate.

| Lane | Pull request | Push to `main` | Nightly / manual |
|---|---|---|---|
| Lint and Type Check (ruff, mypy with main-seeded cache) | yes (required) | yes | yes |
| Security Scan (policy gates, bandit, OSV, npm advisories, release call-graph lint) | yes (required) | yes | yes |
| Build Package (wheel + clean-venv MCP smoke) | yes (required, starts immediately) | yes | yes |
| Test (Python 3.13): aggregation of every correctness lane the event runs | yes (required) | yes | yes |
| Version Alignment (drift, counts, OpenAPI, schemas) | yes | yes | yes |
| CodeQL (Python excluding `tests/`, Actions) | yes (required) | yes | weekly |
| PR Security Gate (pip-audit, self-scan), Dependency Review, Gitleaks | yes | yes (except Dependency Review) | - |
| UI Validate (lint, vitest, schema drift) + UI export build | when UI inputs change | every main push | yes |
| Docs Strict, Helm, Compose, Endpoint packaging | when their inputs change | when their inputs change | yes |
| Native App image and persistence | when its inputs change | yes | yes |
| Python affected tests (shard N/total): affected selection + contract smoke | always (required through aggregation) | yes | yes |
| Full correctness suite, Python 3.13 in 4 shards | never (merge group only) | no | no |
| Full correctness suite, Python 3.11/3.12/3.13/3.14 in 4 shards each (combined 3.11 coverage floor) | no | yes | yes |
| Graph performance, Output scale performance, Extra-gated SDK smoke | no | yes | yes |
| Postgres Integration Contract (live RLS, migrations, schema parity) | relevant inputs (required when selected) | yes | yes |
| Test (Alpine/musl, shard N) | subset only, on dependency/build inputs or `ci.yml` changes | subset on Python changes; full in 4 shards on dependency changes | full in 4 shards nightly, subset manual |
| Docker (multi-arch) + image scans | no | yes | nightly only |
| UI E2E smoke (every packaged route + accessibility, bundle budget) | `ui/`, UI toolchain or `ci.yml` changes | no | no |
| UI E2E (Playwright in 4 shards, bundle budget) | no | every main push | yes |
| UI container smoke | container/build inputs | every main push | yes |
| Dogfood GitHub Action | no | when action inputs change | yes |
| ClusterFuzzLite (`cflite-pr.yml`) | no | short batch on parser changes | weekly long batch |
| Runtime Helm Acceptance (`runtime-acceptance.yml`) | only gateway/runtime changes | every main push | manual |

The UI advisory step reads the committed lockfile without installing packages.
The SDK installation remains because the supply-chain guard builds its output.
Main pushes retain the blocking installed-dependency self-scan in PR Security
Gate; Post-Merge Self-Scan repeats dependency discovery only nightly/on demand
for its SARIF category and automated alerts. Its source scan and SBOM still run
on pushes.

The classifier compares committed TOML for `pyproject.toml` and `uv.lock`.
Only an edit limited to the project's own version can bypass dependency-driven
full-suite/platform selection. Dependency versions, build settings, resolver
metadata, missing revisions and malformed files retain normal routing. Wheel,
version-alignment, selected-domain tests and every-main release proof remain.
The extras audit uses the same comparison and frozen installs; nightly/manual
audits still run every extras group. To roll back routing, revert the workflow
and classifier changes together and obtain fresh main CI proof before release.

The required `Test (Python 3.13)` context also requires Alpine and UI E2E
when their path filters select them (on a PR: the musl subset and the
`UI E2E smoke` job). Failed classification runs both lanes;
a missing, failed, or cancelled selected lane fails that context.

After merge, UI E2E runs as four `UI E2E shard (N/4)` jobs
(`playwright test --shard=N/4`), each building its own standalone server, plus
one `UI container smoke` job. A pull request instead runs one `UI E2E smoke`
job (`e2e/route-catalog-smoke.spec.ts` and
`e2e/route-catalog-accessibility.spec.ts`) when `ui/`, the UI toolchain or
`ci.yml` changes; API and graph contract changes reach the UI through
`UI Validate`. The `UI E2E and container smoke` job, which the release gate
requires by name, passes only when every lane the event requires passed (all
shards after merge, the smoke on a selected PR) and the container smoke
passed (or was not selected). Each shard uploads its own failure traces and screenshots as
`ui-failure-diagnostics-<run>-<attempt>-shard-N`. Specs run file-serial unless
they opt into `test.describe.configure({ mode: "parallel" })`; the largest
spec does, so no shard carries it as one indivisible group.

Full musl runs partition every test file across two runners, with two workers
and a 45-minute limit per runner. Targeted musl runs use one runner. Both full
shards retain the same markers and must pass; a failed shard does not cancel
its sibling.

Branch protection stays strict (PR branches must be up to date with `main`),
so selected tests always run on the merge result that lands. If a shard
becomes the long pole, raise the shard matrix and `--total` together; the
contract tests tie them and check that the shards still partition the suite.

### Required checks

Required branch-protection contexts for `main`, exactly as GitHub reports
them. Repository settings were verified on October 26, 2026 with strict
up-to-date protection and these eight contexts; this file does not enforce settings.

1. `Lint and Type Check`
2. `Build Package`
3. `Security Scan`
4. `Test (Python 3.13)`
5. `Version Alignment`
6. `CodeQL`
7. `Dependency Review`
8. `UI Validate`

`Test (Python 3.13)` is the affected-tests gate: it requires every
`Python affected tests (shard N/total)` job on a PR (through `Python correctness
aggregation`), the Postgres contract, musl subset and UI E2E smoke when
selected, and on main the four-version suite and Docker image. Do not add the
shard jobs themselves: matrix names change with the shard count, and the
aggregation already fails on a failed, cancelled or missing lane. Path-gated
contexts (`Version Alignment` on docs-only changes, `UI Validate` without UI
inputs) report as skipped, which satisfies a required check. Gitleaks,
PR Security Gate (pip-audit, self-scan) and Extras Dependency Audit still run
on every applicable PR without being required. When the list changes, update
`REQUIRED_CHECKS` in `scripts/dispatch_required_ci.sh`,
`scripts/retrigger_stranded_pr.sh` and `.github/workflows/auto-retrigger-stranded.yml`
in the same change.

Affected-test duration estimates control runner count, not a guaranteed PR
wall time. Setup, runner contention, `UI Validate` and the selected Postgres
contract also contribute; use completed CI logs to measure the actual result.

Why a release is still safe: `release.yml` runs
`scripts/check_release_main_ci.py`, which accepts a tag only when the exact
`main` HEAD has completed, successful **push** runs for both `ci.yml` and
`runtime-acceptance.yml`, including the gateway ingest and replica reconnect
job. Missing or skipped runtime evidence fails closed even when the main
pipeline passes. On push (and on
nightly and manual runs), `Python correctness aggregation` requires the
four-version suite and treats a skipped post-merge lane as a failure, and
`Test (Python 3.13)` requires the Docker lane, so a green `main` run means the
full suite, the performance/Postgres lanes, and the release image all passed.
Superseded PR and main-push runs are cancelled within their branch/event
concurrency group. Nightly and manual runs have separate groups. Cancellation
is not a passing result: the release gate still requires a completed successful
push run on the exact current main SHA. Main path routing compares against the
most recent successful main-push ancestor, including changes from cancelled
runs; unavailable history selects all tracked paths. Let the current run finish
before releasing.
A post-merge regression opens a
`ci-regression` issue through `main-failure-alert.yml`, which watches
`CI/CD Pipeline`, `Runtime Helm Acceptance`, and `ClusterFuzzLite`.

When required main checks fail, freeze further merges and releases. Repair the
failure through a reviewed change and verify that exact merged SHA before
resuming. Do not automatically revert or tag over missing or failing evidence.

---

## Documentation-only fast path

The CI path classifier treats a change as documentation-only only when every
changed path is a recognized public documentation file or asset. Empty,
mixed, malformed, workflow, dependency, source, UI, and deployment path sets
fail closed to the normal validation lanes.

For a documentation-only pull request, the five branch-protection contexts
still attach to the head SHA. Changed-domain and shared contract smoke remain
mandatory; unrelated full-suite shards, Postgres and UI container checks skip.
Selected smoke, dependency scanning, type checking and package construction
use explicit fast-success steps instead of disappearing
through workflow-level path filters. Public-doc hygiene, release-copy/count
consistency, strict MkDocs validation when applicable, and the unconditional
gitleaks range scan still run. Main pushes use the same classification; merge
queues, manual runs, classifier failures, and workflow changes run the full
lanes.

The dependency-focused PR security workflow uses the same classifier. CodeQL
and gitleaks remain independent, always-triggered controls so this optimization
does not weaken branch-protection or secret-scanning behavior.

---

## Inspect current protection first

As verified on October 6, 2026, legacy `main` protection uses
`required_status_checks.strict = true` and these five contexts:
`Lint and Type Check`, `Test (Python 3.13)`, `Build Package`, `Security Scan`,
and `CodeQL`. The branch rules endpoint returned no active ruleset rules.
These are a dated settings snapshot, not configuration enforced by this file.
Recheck before diagnosing a blocked merge:

```sh
gh api repos/koda-ai-studio/agent-bom/branches/main/protection/required_status_checks \
  --jq '{strict, contexts}'
gh api repos/koda-ai-studio/agent-bom/rules/branches/main --jq '[.[] | .type] | unique'
gh pr view <PR_NUMBER> --json headRefOid,reviewDecision,mergeStateStatus,statusCheckRollup
```

Strict protection requires validation against current main. Review, signature,
missing-context and other rules can also block merging. Do not weaken protection
to compensate for missing CI evidence.

Security changes and large diffs require an independent written review before
merge. The reviewer records the head SHA, material correctness and security
findings, verification considered, and any unresolved risks. A bare approval
does not satisfy this review policy. GitHub's approval count does not validate
the review's contents; the merge operator must check that evidence explicitly.

## Ready PRs blocked behind `main`

### Symptom

A PR is approved, auto-merge is enabled, and all current checks are green, but
GitHub still says **This branch is out-of-date with the base branch** or
**branch update already in progress**. This becomes common when several small
readiness PRs are stacked behind a strict `main` branch protection rule.

### Root cause

If live protection reports `required_status_checks.strict = true`, advancing
`main` can require a refreshed PR head. When a refresh is needed, follow
the signed local-rebase workflow in `AGENTS.md`, revalidate, and push once with
`--force-with-lease`. Let the new head's checks finish.

### Available recovery automation

`.github/workflows/auto-retrigger-stranded.yml` now runs on PR synchronize
events, every push to `main`, on a 15-minute schedule, and on manual dispatch.
It first runs:

```sh
scripts/refresh_ready_prs.sh
```

The script only refreshes same-repo, non-draft PRs targeting `main`. By default
it further limits writes to PRs with auto-merge already enabled, so exploratory
branches are left alone. Branch refresh and close/reopen retrigger require
`AUTOMATION_GITHUB_TOKEN`, a dedicated GitHub App token or PAT with repo
pull-request/write access. Do not use `GITHUB_TOKEN` for refresh or
close/reopen recovery when unattended CI is required: GitHub token-authored
PR events can require manual workflow approval. Verify the current-head runs
and approval banner before deciding that a workflow is missing.

If `AUTOMATION_GITHUB_TOKEN` is not configured, the workflow now uses a
lower-privilege fallback:

```sh
scripts/dispatch_required_ci.sh <PR_NUMBER>
```

That fallback dispatches the required PR workflows (`ci.yml`,
`pr-security-gate.yml`, and, when needed, `codeql.yml`) through
`workflow_dispatch` for same-repo PR heads that already contain current `main`.
It cannot update stale branches, but it prevents the common "all visible checks
passed, required contexts are still expected" state from wasting a merge cycle.

Manual one-shot refresh:

```sh
PR_NUMBER=<PR_NUMBER> scripts/refresh_ready_prs.sh
```

Dry-run inspection:

```sh
DRY_RUN=true scripts/refresh_ready_prs.sh
```

If the workflow reports "branch update already in progress", leave it alone; the
next scheduled run will verify whether the head advanced and retrigger checks if
needed.

## Stranded PRs (zero check runs on the current head SHA)

### Symptom

A PR sits in `mergeable_state: blocked` with no checks visible in the GitHub
UI. `gh pr view <N> --json statusCheckRollup` returns `[]`. The PR was passing
its required checks before, then someone clicked **Update branch** (or the
`auto-merge` bot did) and the new merge commit has no workflow runs at all.

### Root cause

Inspect the event, token identity, queued runs, and approval state. An empty
check list does not by itself prove that GitHub suppressed an event. Current
GitHub documentation says `GITHUB_TOKEN`-authored `opened`, `synchronize`, and
`reopened` PR events create approval-required runs; ordinary token-authored
pushes do not start push workflows. Dispatch events are explicit exceptions.
A UI branch update is not automatically evidence of a `GITHUB_TOKEN` actor.

See [GitHub's token event behavior](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs).
Check the exact head even when `strict=false`: required contexts still need
valid evidence for that head.

### Fix the stranded PR (one-shot)

```sh
scripts/retrigger_stranded_pr.sh <PR_NUMBER>
```

The script:

1. Resolves the PR's current head SHA.
2. Checks the five branch-protection contexts (`Lint and Type Check`, Python
   3.13, package build, security scan, and CodeQL) against that SHA via
   `repos/.../commits/<sha>/check-runs`.
3. Cancels required-workflow runs for older SHAs on the exact PR branch. If a
   normal cancellation does not finish within a short grace, it uses GitHub's
   force-cancel endpoint; current-head and unrelated runs are never targeted.
4. If any current-head required check is still active, exits without
   retriggering. Downstream jobs such as package build are not created until
   prerequisite jobs finish.
5. If checks are missing or stale after the run is idle, closes the PR and
   immediately reopens it. Use a dedicated App token or PAT for unattended
   recovery; token-authored PR events may otherwise require approval.

The script no-ops when the required check is already present, so it is safe to
run on any PR.

### Event-driven auto-retrigger

`.github/workflows/auto-retrigger-stranded.yml` runs `scripts/retrigger_stranded_pr.sh`
against every synchronized PR whose current head SHA has zero or stale
required checks. It runs immediately after a PR push, after `main`
advances, every 15 minutes, and through `workflow_dispatch` for on-demand. Once this workflow is on the
default branch and `AUTOMATION_GITHUB_TOKEN` is configured, eligible stranded
PRs can recover automatically. The fallback schedule is every 15 minutes and
GitHub may delay it; there is no five-minute recovery guarantee.

When the automation token is absent, the workflow falls back to
`scripts/dispatch_required_ci.sh` and dispatches required workflows for current
same-repo PR heads. This is less powerful than branch refresh, but it is enough
for PRs that are already rebased and only missing required status contexts.

Operator-side troubleshooting if a strand persists past ~10 minutes:

- Did the workflow itself run? `gh run list --workflow=auto-retrigger-stranded.yml --limit 5`
- Is `AUTOMATION_GITHUB_TOKEN` configured? Without it the workflow can dispatch
  required checks for current heads, but cannot refresh stale branches or use
  the close/reopen retrigger path.
- Was the PR younger than `MIN_AGE_MINUTES` (3 min by default)? It's intentionally
  skipped to give the initial `pull_request` workflow a chance to start.
- Did `gh api commits/{sha}/check-runs` return zero, or did branch protection
  change? Keep `REQUIRED_CHECKS` aligned with the protected contexts.

### Merge-queue configuration

No merge queue is enabled. The repository is now owned by the
`koda-ai-studio` organization and is public, which is the case GitHub
documents merge queues for; confirm availability in the repository settings
before relying on it. `ci.yml`, `codeql.yml` and `pr-security-gate.yml`
declare `merge_group: types: [checks_requested]`. In `ci.yml` a merge group
skips the path classifier, so every path-gated lane runs, and it runs the
full 3.13 shards instead of the affected tests plus the post-merge
performance lanes. `Lint and Type Check`, `Build Package`, `Security Scan`,
`Test (Python 3.13)`, `Version Alignment`, `UI Validate` and `CodeQL`
therefore report on a merge group.

`Dependency Review` (`dependency-review.yml`) runs on `pull_request` only. A
required check that never reports on `merge_group` makes every queued merge
fail, so before enabling a queue with the proposed list either add a
`merge_group` trigger that passes without a PR diff or leave it out of the
required contexts. To enable: Settings, Branches, edit the `main` rule, turn on
"Require merge queue" and keep the required contexts above.

Keep strict up-to-date protection: it is what makes the PR's sharded suite run
on the commit that lands. Use `scripts/enable_merge_queue.sh --check` for
read-only inspection. Do not configure the shard or full-correctness matrix
job names as separate required contexts: the stable `Test (Python 3.13)`
aggregation already requires all of them. Retain the exact-main release gate.

---

## Other recurring CI gotchas

### `pull_request_target` workflows

Workflows that need write access to the repo from a PR (e.g. the Dependabot
lockfile normalizer) use `pull_request_target` so the `GITHUB_TOKEN` carries
write scopes. Two hard rules apply to anything we add to that family:

1. Never run a script defined inside the PR's working tree (`npm run …`,
   `make …` against PR `Makefile`, `tox` against PR `tox.ini`, etc.). A PR
   can redefine those scripts to exfiltrate the privileged token.
2. Always use `--ignore-scripts` (or the equivalent) on package installers so
   transitive postinstall hooks cannot execute either.

`.github/workflows/dependabot-ui-lockfile-normalize.yml` is the canonical
example: it runs `npm install --package-lock-only --ignore-scripts` directly
instead of `npm run lock:normalize`.

### Required checks renamed

If a workflow job is renamed, its old name stays as a required context until
someone updates the branch protection rule. Symptom: every PR is blocked on a
check name that no longer exists. Fix: Settings → Branches → main protection
rule → re-select required contexts.
