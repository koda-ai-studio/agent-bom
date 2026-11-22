# Agent Guidelines for agent-bom

This is the root operating guide for **any agent or coding assistant** working
in this repo — Claude, Codex, Cursor, Continue, Aider, Windsurf, or human
contributors using one. Follows the [agents.md](https://agents.md) convention.

Keep it concise and route deep implementation details to the owning docs,
tests, or package directories.

**Coding agents: load the repo skills first.** `.agents/skills/develop`
(test-first loop and the checks CI runs) and `.agents/skills/secure-change`
(what a change must never do) apply to every change. Codex reads
`.agents/skills/`; Claude Code reads the same files through `.claude/skills`.
CI enforces both: a PR that changes `src/agent_bom/**.py` without touching
`tests/` fails unless a maintainer applies `no-tests-needed`, and every
`AGENTS.md`, `CLAUDE.md` and `SKILL.md` in the repo must scan benign with
agent-bom's own skill auditor.

`agent-bom` is an open security scanner and self-hosted control plane for
AI-era infrastructure. The product must prove value across local scans, CI
evidence, fleet inventory, graph-backed findings, MCP/runtime enforcement, and
customer-controlled deployments.

**Product vision:** plug-n-play for humans and agents — easy, accurate,
efficient, scalable, secure, up-to-date. Inventory → findings → compliance →
graphs (environments, lineage, identity, scans, MCP, agents).

## Operating Contract

Every material change should satisfy four lenses:

| Lens | Question | Evidence expected |
|---|---|---|
| Product manager | Is the first run obvious, useful, and honest? | Clear command, visible artifact, no inflated claims, next step documented |
| Sales engineer | Can this be proven live in a buyer environment? | CLI/Docker/API/Helm/runtime smoke evidence or a specific reason it was not run |
| Account executive | Is the buyer/problem/value clear? | Framing tied to AI/MCP supply-chain risk, self-hosted adoption, and governance evidence |
| Software/security engineer | Is it safe, accurate, scalable, and operable? | Tests, strict validation, auth/tenant/audit behavior, failure mode, and rollback notes |

Do not present roadmap work as shipped product. If a claim is user-visible, tie
it to code, tests, screenshots, docs, or live command output.

## Model selection and handoffs

For Codex, prefer GPT-6 Astra with High effort for full-stack implementation;
Extra High for identity, authorization, tenant isolation, containment, audit
integrity and concurrency review. Sol with High is suitable for bounded UI and
implementation work; Sol with Medium for straightforward documentation and CI
fixes. These are workflow preferences, not measured correctness guarantees.
Honor explicit user choices and available models. Other assistants should use
an available model appropriate to the same risk and scope.

AGENTS.md does not change runtime model settings. Select model/effort through
the supported client control; never claim a switch unless confirmed. Do not
change global defaults or create new tasks merely to apply this guidance.

At a PR boundary, preserve a private handoff with base/head SHAs, worktree,
completed versus remaining items, exact test results, blockers and next action.
A new session is useful for independent review or a distinct deliverable, not
required for every model change. Recheck main and the diff before resuming.
Keep detailed delivery trackers outside the public repository.

## Evidence preservation

Do not delete or rewrite audit records, traces, chat artifacts, or failed-run
evidence to conceal activity or make validation appear successful. Authorized
retention, redaction and cleanup must preserve the required audit receipt and
must not silently discard evidence needed by an active investigation.

For audit/security changes, separate agent-controlled telemetry from independent
collector and provider evidence. A hash chain detects some tampering; it is not
proof against deletion or rewriting by an actor controlling both the records
and their checkpoint/key. Document this boundary and test truncation, replay,
missing events and denied evidence deletion where applicable. Treat a gap as
missing evidence, not proof of malicious intent or a clean result.

## Project Structure

```text
agent-bom/
├─ src/agent_bom/              # Python package: CLI, scanners, API, MCP, runtime, graph
├─ ui/                         # Next.js dashboard
├─ deploy/helm/agent-bom/      # Kubernetes and Helm control-plane/runtime chart
├─ integrations/               # Claude Code and Codex plugins, MCP registries, OpenClaw/Cortex/Docker assets
├─ docs/                       # repo docs, security evidence, architecture, skills
├─ site-docs/                  # published documentation site
├─ tests/                      # Python regression and contract tests
├─ sdks/typescript/            # TypeScript SDK surface
└─ .github/workflows/          # CI, release, dependency, and security automation
```

High-signal entry points:

- CLI scan path: `src/agent_bom/cli/agents/__init__.py`
- scanner driver metadata: `src/agent_bom/cli/_scanner_registry.py`
- API app and routes: `src/agent_bom/api/server.py`, `src/agent_bom/api/routes/`
- graph persistence/API: `src/agent_bom/db/graph_store.py`, `src/agent_bom/api/routes/graph.py`
- MCP tools/server: `src/agent_bom/mcp_server.py`, `src/agent_bom/mcp_tools/`
- runtime proxy/gateway: `src/agent_bom/proxy.py`, `src/agent_bom/gateway_server.py`
- dashboard: `ui/app/`, `ui/components/`, `ui/lib/`
- deployment chart: `deploy/helm/agent-bom/templates/`

## Product Lanes

Use this framing when editing public docs, UI copy, release notes, demos, or
examples:

1. **Scan** — CLI, Docker, GitHub Action, and cloud connect (from a self-hosted
   control plane) produce findings, SARIF, SBOMs, HTML reports, and graph
   exports. “Local” is one entry point, not the product boundary.
2. **Centralize evidence in a control plane** — fleet sync, REST API, Helm/EKS,
   and the browser UI centralize inventory, graph state, compliance, audit, and
   governance.
3. **Enforce runtime behavior** — MCP server mode, proxy/gateway, and Shield
   SDK turn the same model into assistant and tool-call controls.

These lanes are one product and one evidence model. They do not weaken the
self-hosted story: production control planes run in the customer's own cloud,
VPC, Kubernetes cluster, database, identity, and audit boundary.

## Integration Bar

Integrations are distribution surfaces, not footnotes. For integration work,
document the first command, credential boundary, artifact, and next step.

Important integration families:

- MCP/coding agents: Claude, Cursor, Windsurf, VS Code, Cortex Code, OpenAI
  Codex CLI, and other MCP clients.
- Skills/registries: OpenClaw skills, Cortex Code skill, MCP Registry,
  Smithery, Glama, Docker MCP registry.
- Developer workflow: CLI, Docker, GitHub Action, SARIF, SBOM, pre-install
  `check`, PR comments, and CI gates.
- Cloud and AI infra: AWS, Azure, GCP, Snowflake, Databricks, CoreWeave,
  Nebius, Hugging Face, OpenAI, W&B, MLflow, Ollama.
- Runtime and app frameworks: MCP proxy/gateway, Shield SDK, Anthropic/OpenAI
  SDK patterns, LangChain, CrewAI.
- Governance and observability: Postgres/Supabase, ClickHouse, Snowflake paths,
  OTEL, SIEM/export hooks, compliance bundles.

## Core Commands

```bash
uv run pytest -q
uv run ruff check src tests
uv run mypy src/agent_bom
uv run agent-bom scan --demo --offline

cd ui
npm run verify:toolchain
npm run typecheck
npm test -- --run
npm run build
```

Run narrower checks when the change is narrow, but list exactly what you ran in
the PR body.

Minimum verification matrix:

| Change scope | Minimum verification |
|---|---|
| CLI/scanner behavior | targeted `tests/test_cli*` or scanner tests plus one real `agent-bom scan` smoke |
| API routes/models | targeted API tests plus schema/codegen check when contracts change |
| graph persistence/API/UI | graph API tests plus a live or fixture graph with non-empty nodes and edges |
| runtime proxy/gateway | targeted runtime tests plus a live JSON-RPC smoke when feasible |
| Helm/deploy | `helm template` for affected profiles, asserting rendered structure (not just exit 0), plus YAML lint where available |
| UI | `npm run verify:toolchain`, typecheck, tests; screenshots in both themes at 1440 and 390 px, including the first frame, reviewed before push |
| docs/positioning only | stale-command search and `git diff --check`; do not claim untested capabilities |
| dependency/toolchain | package-specific install, lockfile/toolchain verification, and affected tests |

## On task start, ALWAYS

- `git fetch origin main` before any audit and compare against the relevant
  base branch. Rebase, merge, or pull only when the current worktree is meant
  to move.
- Read recent commits (`git log --oneline -15`) and open PRs (`gh pr list`).
- Check `pyproject.toml` version vs the latest tag vs PyPI before claiming
  release state.
- For end-user audits, install fresh from PyPI in a clean venv. Do not trust
  the working tree.

## Never

- AI/tool co-author trailers or tool-credit prefixes in commits, PR titles, or
  CHANGELOG entries — they ship into GitHub release notes.
- Name or compare against other products in issues, PR titles/bodies, commits,
  code comments, docs, marketing, release notes, or benchmark claims, including
  as a design reference — describe our own capabilities and users' needs. Integration code and supported-upstream docs may name a third-party
  service when the exact name is required for users to configure it.
- Release with broken imports, red tests, or unreleased `[Unreleased]`
  CHANGELOG entries or `changelog.d/` fragments left after tagging.
- Claim a file, feature, or behavior exists without reading the code that
  proves it.
- Open more than 4 PRs simultaneously in the same queue — open sequentially
  as each merges.
- Re-tag an existing version. Bump and tag forward only.
- `git push --force` to `main`, `--no-verify`, `--no-gpg-sign`, or amend
  published commits without an explicit user request.
- Commit private strategy, GTM/IP plans, named prospect/partner lists,
  advisor/individual targeting notes, AE/commercial scorecards, harsh
  pilot re-rate tables, or agent-session / persona audit ledgers into the
  public tree (`docs/`, `docs/audits/`, `docs/archive/AUDIT*`,
  `site-docs/`, CHANGELOG, UI copy, PR titles/bodies). Keep that material
  in private notes or chat. Public docs are product evidence and operator
  runbooks only — not agent-session review write-ups. Enforced by
  `scripts/check_public_docs_hygiene.py`.

## Always

- Verify before claiming. "Looks good" without running or reading the code is
  not allowed.
- Full-stack alignment on every material change: deps → data model → DB →
  API → middleware → outputs (JSON / SARIF / CycloneDX / SPDX / Markdown /
  HTML) → CLI → UI → tests → docs → CI guards → Helm / Docker.
- Canonicalize platform invariants server-side; don't raise on ad-hoc input
  where Pydantic validators can normalize.
- Non-trivial features cover foundation → mechanical → surface → lock-in.
  Default to four PRs; when the user requests consolidation, combine related
  stages into fewer reviewable PRs without dropping their verification gates.
- When Phase N supersedes a Phase N-1 component, remove the old one in the
  same PR.
- Auth-by-default. New endpoints reject anonymous traffic unless the contract
  explicitly allows it.

## Engineering bar (six lenses, every change)

1. **Correctness** — tests pass; semantics match docs.
2. **Performance** — measured, not asserted; published benchmarks are real.
3. **Security** — auth-by-default, redaction-aware, audit-chain-signed where
   applicable.
4. **Observability** — healthz / correlation_id / OCSF-shaped logs / metric
   labels.
5. **Persistence** — backends abstracted (SQLite default, Postgres ready,
   ClickHouse planned); RLS where multi-tenant.
6. **Enterprise readiness** — Helm + values examples + EKS + Docker Compose +
   Railway (MCP server) + airgap path.

## PR / commit style

- Factual and impersonal. No chat-style prose ("you flagged X", "as we
  discussed").
- Title: `feat(area): ...`, `fix(area): ...`, `docs(area): ...`,
  `chore(deps): ...`, `refactor(area): ...`.
- Body: Summary (1-3 bullets) → Verification (commands run) → Notes (if any).
- Pin every claim to evidence (test name, command, screenshot, doc path).

## Repo Rules

- Keep changes scoped. Do not mix dependency bumps, product docs, UI changes,
  and scanner behavior unless one is required by the other.
- Do not add new top-level modules under `src/agent_bom/*.py`. Put new code in
  an existing package (`api/`, `graph/`, `runtime/`, `cloud/`, `mcp_tools/`,
  …). The flat namespace is frozen by `scripts/check_package_layout.py`;
  `docs/CODE_MAP.md` says which package owns what.
- Every commit is signed, including commits made in helper worktrees; check
  `git log --format=%G?` shows `G` before pushing. Avoid synthetic GitHub update-branch churn; use
  local rebase plus `--force-with-lease` when a PR branch must be refreshed.
- Do not edit generated artifacts unless the owning generation command is run
  and documented.
- For bug fixes, add or update a regression test that fails without the fix.
- For user-visible dashboard or graph changes, verify readability in light and
  dark themes and avoid dense unreadable canvases as the first view.
- For auth, tenant, audit, firewall, gateway, and proxy changes, document
  fail-open/fail-closed behavior explicitly.
- Never surface a raw exception string to an HTTP response body or a log line on
  API / cloud / runtime paths — raw exceptions carry secrets, ARNs, paths, and
  connection strings. Route response text through
  `agent_bom.security.sanitize_error(exc)` (use `generic=True` on
  auth/secret/encryption/session/broker paths) and log text through
  `sanitize_text(...)`. The `scripts/check_exception_sanitization.py` guard
  (pre-commit + CI) fails on new `detail=str(exc)` / `detail=f"...{exc}"` bodies
  and raw-exception log f-strings; use `# exc-safe: <reason>` only for a vetted
  exception.
- Before opening or updating a PR that touches `src/agent_bom/api/` routes or
  models (and after any change that regenerates a checked-in artifact), run
  `make preflight` — it runs the same drift gates as CI's **Version Alignment**
  job (OpenAPI `docs/openapi/`, v1 schemas `docs/schemas/v1/`, product-surface
  contract, release consistency, env-var reference, SDK `patterns.json`). Use
  `make preflight-fix` to regenerate the artifacts, then review and commit them.
  Skipping this is the most common cause of an approved PR going red on a stale
  generated file — regenerate locally instead of round-tripping through CI.
- Before the first push, run the changed-domain selection from
  `scripts/pytest_ci_plan.py targeted` plus the current CI contract smoke set.
  UI tests and `make preflight` alone do not cover all storefront/doc contracts.
- Run the tests for the code you touched **before** pushing (`pytest` on the
  affected `tests/test_*.py` files; test order is randomized by pytest-randomly,
  so a green local run on your files is the fastest signal). Push a PR branch
  **once and let CI finish** — CI uses `cancel-in-progress` on non-`main`
  branches, so stacking rapid commits (formatter, merge-main, review-dismissals)
  cancels the in-flight run and the canceled jobs surface as red "failing"
  checks. When a check's annotation reads "The operation was canceled," that is a
  supersede/cancel, not a test failure: re-run the job (`gh run rerun --failed`)
  and leave the branch untouched until it completes — do not debug it as a code
  bug.
- For docs, avoid vague capability lists. Prefer "first command -> artifact ->
  next step."

## Setup and pre-push checks CI enforces

- **Setup:** open the Codespace / dev container, or run `uv sync --extra dev`
  then `uv tool install pre-commit && pre-commit install`. `pre-commit` is not
  in the `dev` extra, so `uv run pre-commit` fails on a fresh checkout.
- **Size ratchet:** no file over 1,000 lines or Python function over 150
  (`python scripts/check_line_ceiling.py`, Python and `ui/`), and function
  size, `api/` imports and deferred imports may only shrink. Run
  `python scripts/check_architecture.py --base-ref origin/main`; split code
  into a subpackage instead of growing a large file.
- **Optional dependencies stay lazy:** CI test jobs install `dev` plus at most
  `api`, `mcp-server` and `otel`. Do not import `psycopg`, `boto3` or a cloud
  SDK at module level in shared code or tests. Run your changed tests in that
  environment, not only with `--all-extras`.
- **Postgres-only tests** must be listed in the "Run real Postgres storage
  contract" step of `.github/workflows/ci.yml`, or CI never runs them.
- **Changelog:** add a `changelog.d/<slug>.md` fragment (`### Fixed`,
  `### Added`, ... with bullets; see `changelog.d/README.md`). Never edit
  `CHANGELOG.md` in a feature PR; the release step runs
  `python scripts/assemble_changelog.py --version X.Y.Z`.
- **Product metrics** (`docs/PRODUCT_METRICS.*`) are a release-time artifact:
  do not regenerate them in a feature PR. The PR check only fails when the
  version or metric set changes; the release runs the strict
  `--check --release` form.
- **Generated artifacts:** `make preflight` checks most of them (OpenAPI, v1
  schemas, reference evidence lab, vendor coverage, env-var reference). Graph or storage changes also need
  `python scripts/generate_graph_data_model.py --check`; plugin skill changes
  need `python scripts/render_plugin_skills.py --check`. Regenerate with the
  owning script and commit the result.
- **Goldens:** refresh scan and renderer goldens deliberately with
  `AGENT_BOM_UPDATE_SCAN_GOLDENS=1` / `AGENT_BOM_UPDATE_OUTPUT_GOLDENS=1` and
  review the diff; never hand-edit them.
- **Product screenshots:** a change to their inputs (`ui/`, `src/agent_bom/graph`,
  the reference evidence lab) needs `npm run capture:product-proof` from a clean,
  committed tree, after a clean `npm run build` (delete `ui/.next` first); otherwise
  `check_release_consistency.py` fails on the recorded digest.
- **UI:** run `npm run typecheck` and the full `npx vitest run`; contract tests
  pin exact lines of scripts such as the capture script.

## Release Readiness

Before a release readiness claim, check:

- latest `main` CI state and open release-blocker issues
- fresh-install first-run smoke (PyPI or local wheel in a clean venv, depending
  on release stage): `agent-bom quickstart --run` → `agent-bom serve` →
  `/health` and `/v1/overview` load without 401 → the dashboard shows data
- Docker/Helm smoke for the advertised deployment path
- API `/health` and `/docs` behavior under the intended auth mode
- MCP tool listing and strict-argument behavior
- graph/finding links with real scan data, not only synthetic fixtures
- runtime proxy/gateway smoke when runtime is part of the release narrative
- README, Docker Hub README, docs site, version surfaces, and changelog alignment

If a check cannot be run, say so directly and keep the claim narrower.

## Learned rules (from past failures)

Each rule below comes from a real incident in this repo. Treat them as
additions to the sections above.

### PRs and CI

- Push to your open PR when its files fit the change; open a new PR only when the change must merge or revert on its own timeline. One coherent PR per epic beats many 1-file PRs: each costs a full CI run and a review.
- Do not merge PRs or push tags. Hand merge, tag, portal and identity steps to a maintainer; never route around a denied action.
- Given "use best practice", pick the conservative, fail-closed, standard option, proceed, and state what you chose.
- Develop with targeted tests (`scripts/pytest_ci_plan.py targeted`, `pytest -n 2 --timeout=120`) plus cheap gates; let GitHub CI run the full tiers. Never run `make ci-smoke`, `scripts/ci_local.py` or `pytest -n auto` while other agents share the machine.
- When CI fails, collect the failure list from every job (`gh run view <id> --log-failed`) and fix them all in one push.
- Never call a red check "expected" or "flaky" until you have read its failed log and the workflow step, and compared with the last green `main` run. If `main` is red too, it is a regression: fix it.
- Fix flaky specs at the root (for example, a click on a canvas whose camera is still moving) and prove it with `--repeat-each=10` on a fresh build. Do not just re-run.
- "Merged" means merged into its base branch. Before building on a PR, confirm its code is on `main` (`git merge-base --is-ancestor <sha> origin/main`); stacked PRs merged into a deleted side branch strand work.
- Before opening a PR, merge or rebase onto current `main` and check `git diff origin/main...HEAD --stat` lists only files you meant to change; a stale base shows phantom deletions, and squashes can silently revert others' work.
- A clean merge is not a correct merge. After any merge or rebase, run `python -m compileall -q src tests` and the tests for every module the merge touched (signature and body lines can merge into a `def` containing `await`, or into duplicate kwargs).
- On rebase conflicts in generated files, take the base branch's version, then regenerate with the owning script; never hand-merge them.
- After any merge to `main`, rebase your remaining open PRs and re-gate them. If a co-maintainer used "Update branch", fetch and rebase onto the remote branch; never force over it.
- Review PRs from other contributors with an independent pass before acceptance: correctness, security, any ratchet or baseline edits, and semantic conflicts with open PRs (merge them together and run both test sets).
- Review GitHub UI autofix commits before accepting them: they add a co-author trailer and have deleted re-exports other modules used.
- Keep at most two PRs running CI at once; extra dispatch matrices starve the shared runner pool.
- Keep the PR lane and the merge-queue run at five minutes or less. Long suites belong on `main` push and nightly; check the budget before adding a blocking job, and prefer shared fixtures/seeds over per-test reseeding.
- Required check names must report on both `pull_request` and `merge_group`, or the queue blocks forever.
- Automatic CI-failure issues need a failure-streak threshold and must close themselves on green. Fix the cause; do not close them by hand.
- Poll CI from one loop at most every few minutes (`gh run view --json status`); one `gh run watch` per run exhausts the shared GitHub API quota.
- Known trap: `Auto-Retrigger Stranded PRs` can cancel a manual `workflow_dispatch` CI run on a PR branch (it fired on a PR-body edit).

### Pre-push traps CI catches but a narrow local run misses

- Run any CI job your change could touch, not a convenient subset: lint (`ruff check` and `ruff format --check` over `src tests scripts`), `bandit -r src/ --severity-level medium`, `scripts/check_architecture.py --base-ref origin/main`, and mypy with CI's extras (`--extra dev --extra aws --extra azure --extra gcp`).
- Run make targets as `uv run make …`; a bare `make` can resolve a different package set and fail falsely.
- Prefer literal SQL constants over f-string composition (bandit B608) rather than adding `# nosec`.
- Postgres suites skip locally without `AGENT_BOM_POSTGRES_URL`; replay CI's Postgres contract step against a private cluster when you change storage.
- Vitest is not Playwright: UI changes that affect rendering also need `npm run build`, the Playwright suite and `npm run bundle:check`.
- Any commit after the product-proof capture (even backend-only) can stale `docs/images/product-screenshots.json`; recapture after your last commit, right before push.
- If `main` moved while you gated, merge it in, recapture and re-gate before pushing; push only when `git merge-base --is-ancestor origin/main HEAD` holds.
- Never pipe a gate step into `| tail` or `| head` before `&&`; the pipe hides the exit code. A gate script that prints no test summary did not run tests.
- Dockerfile base or apk/apt pin changes: build the image locally and check the pins in the pinned base; `Docker (multi-arch)` does not run on PRs.
- Secret scanning: run CI's pinned gitleaks version over `origin/main..HEAD` before push (newer local versions pass literals CI flags). Do not write synthetic secrets to disk either (CodeQL flags clear-text storage); substitute them in memory. A `.gitleaksignore` comment never quotes the value.
- Committed fixture dependency manifests with old versions fail the repo-wide dogfood `agent-bom fs .` scan. Commit them as `<name>.fixture` and restore real names in a temp copy at test time.
- `claude plugin validate --strict` accepts invalid skill YAML; `tests/test_plugin_skill_frontmatter.py` catches it.
- Do not bind `from module import func` at module level in `src` where tests patch `module.func`; call through the module.
- Keep `rich`, `pydantic` and other runtime imports out of core modules that `agent_bom.graph` imports.

### Test-writing traps

- Never pass a custom pytest `--basetemp` to scan suites: a dot-prefixed path is skipped by model scanning, and a path outside home/cwd/system temp is refused as a scan root. Both guards are correct.
- Goldens that embed fixture paths must build fixtures under a low-entropy root (see `_case_root` in `tests/test_scan_characterization.py`); macOS temp paths trigger entropy redaction that Linux CI does not.
- Fixtures that guard process-global state (loggers, env) must snapshot at import or session scope, not function scope. For order-dependent flakes, instrument the setter rather than sampling state.
- "Exits 0" or "renders" is not a test. Assert the rendered structure (for example, every Helm ingress host has non-empty paths) and the content of SBOM/SARIF/report output.
- Disk-full or ENOSPC failures are environment problems, not regressions in the test that happened to hit them.

### Quality bar

- Find the class, not the instance: sweep every store, route and surface for the same defect, fix each test-first, and add an invariant test (with a known-bad fixture and a reasoned allowlist) so CI blocks its return.
- Tenant data: `tenant_id` is in every primary key, unique and dedup key; upserts are tenant-scoped; every read, update and delete filters by tenant. Prove it with a two-tenant same-key test, and a cross-process test for append-only or hash-chained stores.
- Upstream errors, rate limits, outages and truncation degrade gracefully (retry/backoff, partial-data status), never crash and never silently drop data. Prefer bounded-concurrency batches over per-item fan-out.
- One derivation per number: counts must reconcile across CLI, API, UI and every export format; caches key on tenant and revision and stay correct across restart; IDs are stable across rescans. Report before/after timings for performance claims.
- A feature is not done while it is "computed but never surfaced" or held up by a stub, cap or skip. Demo data supplies raw facts only; never hand-draw graph edges or paths in demo code.
- Identity work covers human, CI/headless and service/agent principals across provision → authenticate → authorize → rotate → deprovision; prefer tokens and short-lived credentials over passwords.
- Rename a route only with redirects for the old path in the same PR.
- Files and functions stay small and single-purpose; the size ceiling is a limit, not a target. Split behaviour-preservingly (golden on unmodified `main` first, façade re-exports for patch points) and fix ratchet hits by moving code, never by raising baselines.
- Audits report a score per dimension (including cost-efficiency and adoption/time-to-first-value); no dimension may fall below 8/10, and an overall average never stands in for that.
- Verify outside audit findings in code before accepting or dismissing them; both false positives and real defects occur.

### Release gates (in addition to Release Readiness)

- Exercise the path a customer onboards through, not only scan jobs: bulk ingest at scale, `/health` latency under concurrent write load, a restart after large ingest, mid-batch failure atomicity and old timestamps.
- Render every heavy UI page against seeded data with the browser console open, including empty, zero-finding and invalid-timestamp inputs; API 200s do not catch render errors or dishonest "pass" states.
- Before signing a release GO, run an adversarial second pass that tries to refute "it works".
- Run a full STRIDE self-review per release and keep `docs/THREAT_MODEL.md` matching the code (verify mitigations in code, not in docs).
- Run `scripts/preflight_release.sh` from a detached worktree of `origin/main` with the repo venv, chain the tag command with `&&`, and only after `ci.yml` and `runtime-acceptance.yml` have completed green on that SHA. If the release gate failed only because CI was still running, re-run it; never move the tag.

### UI, CLI output and visual verification

- Before approving or pushing any change to UI, graph rendering or CLI output (yours or an agent's), look at it: real screenshots in both themes at 1440 and 390 px including the first frame without "fit all", or the real command output. Green tests and agent reports are not approval.
- Before judging UI on a local server, confirm `src/agent_bom/ui_dist` is newer than the last `ui/` commit; rebuild with `scripts/build-ui.sh`. A stale bundle is served without any version warning.
- Every list, table or queue paginates with a visible pager and page size, pre-applied filters and dense rows. A paginated page of oversized cards still fails; check row density before adding a pager.
- Dense but not crowded: one shared shell and component set, consistent spacing and per-entity icons, colour only for severity/status, summary first with detail behind expanders/tabs/drawers, and empty/loading/error states everywhere. Fix the shared system before individual pages.
- CLI and report output lead with the summary and "fix these first", group duplicate remediation lines, show a status legend, keep priority, severity and effort as separate labels, and put the raw list behind `--verbose`. Use one severity, colour and status vocabulary across CLI, HTML, report and UI; design for 10k+ findings (virtualized tables, streaming exports).
- Public demo and docs show only fake identifiers (for example AWS's reserved account `123456789012`). Hide operator env vars and restart instructions from demo visitors.

### Product semantics (change only with a maintainer decision)

- Scans with incomplete vulnerability data never exit 0; air-gapped users opt out with `--allow-stale-db` / `AGENT_BOM_ALLOW_STALE_DB`, and MCP/API return a structured status.
- `graph_reachable` means inbound reachability via any attack path; a path through an agent is a stronger signal and must rank higher. Outbound blast radius is a separate, separately named field. Ingested reachability claims must carry evidence.
- Operator-supplied VEX (`--vex`, explicit API/config) with `not_affected`/`fixed` suppresses a finding visibly with its justification; VEX discovered inside scanned artifacts is evidence only.
- Unscored advisories take severity from CVSS, then the advisory's own rating, then distro, then `medium` as a last resort, recorded in `severity_source` and labelled "unscored".
- Finding status, first seen, last seen and resolved-on derive from scans. Resolve only on a later complete scan of the same scope (or a deleted asset confirmed by a complete inventory scan); never from a partial or failed scan. Assets no longer scanned go "stale", not resolved. A returning finding reopens with its original first-seen.

### Shared-machine hygiene (local agents)

- Check load (`uptime`) before heavy work; run heavy commands under `nice`, one at a time per agent, at most two full test gates on the machine, with `timeout` on long commands.
- Use a private Postgres cluster (own data dir, random free port) and stop it when done; never run DDL against a port you did not start.
- Use a private `--kubeconfig` for kind, kubectl and helm; never modify `~/.kube/config` or select a context for the user.
- Delete only exact paths you created; never glob a shared temp or scratch root. Dry-run delete filters, do not suppress `find` errors in them, and never delete pytest temp while any pytest is running.
- After a PR merges, remove its worktree and local branch once its content is on `main`. Leave other agents' dirty or recently active worktrees alone; delete a remote branch without a PR only when every file it changed is identical on `main`. Ask before removing named Docker volumes.
