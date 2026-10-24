---
name: develop
description: Use for any code change in agent-bom (feature, fix, refactor). Test-driven loop, verify before claiming, and the local checks CI enforces, so a PR is green on its first run.
---

# Develop in agent-bom

Follow this loop for every change. Read `.agents/AGENTS.md` once per session;
it holds the product rules this skill assumes.

## 1. Understand before editing

- `git fetch origin main` and branch from it. Read `docs/CODE_MAP.md` to find
  the package that owns the change; never add a new top-level module under
  `src/agent_bom/`.
- Read the code you will change and its tests. Do not describe a file,
  function or flag you have not opened.

## 2. Test first (red)

- Write the test that proves the behaviour **before** the implementation.
- Run it and confirm it fails for the right reason (an assertion about the
  behaviour, not an import error or typo). Keep the failing output: the PR
  body quotes it.
- Bug fix: reproduce the bug as a regression test. Feature: one test per
  acceptance criterion in the issue.
- Assert structure and values, never just "exit code 0" or "no exception".

## 3. Make it pass (green), then refactor

- Write the smallest change that makes the test pass; run it again.
- Refactor with the tests green. Keep functions short and files under 1,000
  lines; `python scripts/check_architecture.py --base-ref origin/main` must
  pass.
- Never weaken, skip or delete an existing test to get green. If an existing
  expectation is wrong, change it in its own commit and say why in the PR.

## 4. Run what CI runs

From `.agents/AGENTS.md`, "Setup and pre-push checks CI enforces":

```bash
uv run ruff check src tests && uv run ruff format --check src tests
python scripts/check_architecture.py --base-ref origin/main
python scripts/pytest_ci_plan.py targeted --root . <changed files>   # then run those tests
make preflight          # when API routes/models or generated artifacts change
```

Run the changed tests in an environment with only
`uv sync --extra dev --extra api --extra mcp-server --extra otel`, because CI
test jobs do not install other optional dependencies. UI changes: `npm run
typecheck` and `npx vitest run` in `ui/`.

## 5. Open the PR

- Conventional title (`fix(area): ...`). Body: summary, the red output before
  and the green run after, every command you ran, and fail-open/fail-closed
  notes for auth, tenant, gateway or proxy changes.
- A PR that changes `src/agent_bom/**.py` without touching `tests/` fails the
  "Source changes carry tests" check; only a maintainer can waive it.
- No AI co-author trailers or tool-credit prefixes in commits, titles or the
  changelog.

Before any of this, read the `secure-change` skill: it lists what a change in
this repository must never do.
