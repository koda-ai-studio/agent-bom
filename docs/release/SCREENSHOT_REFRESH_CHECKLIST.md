# Product Screenshot Refresh Checklist

Use this checklist when refreshing product screenshots for README, docs site,
Docker Hub, release notes, or marketplace evidence. It turns the capture
protocol in [`docs/CAPTURE.md`](../CAPTURE.md) into a PR-ready release gate.

## Preflight

- Start from the release branch or tag that will publish the screenshots.
- Confirm the visible version in `pyproject.toml` matches the intended release.
- Build the packaged dashboard; do not capture from an archived UI or a dev
  page that shows transient build state.
- Generate bundled demo data offline and push that exact payload to the API.
- Keep local workstation discovery, private tenants, and customer data out of
  the capture database.

## When

Refresh once per release, in the release-prep PR, after every other change for
the release has merged. Ordinary PRs do not re-capture: PR CI tolerates a stale
capture-inputs digest and attaches Playwright screenshots as workflow artifacts
instead. The release workflow runs
`python scripts/check_release_consistency.py --release` and fails unless the
committed set was captured from the tagged source. The tag must equal the
`main` head, so merge the release-prep PR last.

## Capture Set

`npm run capture:product-proof` captures exactly the images that `README.md`,
`docs/` and `site-docs/` embed, and writes those entries to
`docs/images/product-screenshots.json`. To add a screenshot, embed it in a doc
and capture; to retire one, remove its last reference and delete the file.

| Asset | Required proof |
|---|---|
| `dashboard-live.png` | Overview top frame with visible version, posture grade, unique findings, scan coverage, and operational lanes. |
| `dashboard-paths-live.png` | Overview with Compliance & frameworks and Findings by security area expanded. |
| `mesh-live.png` | Focused active agent → MCP server → package → finding path with title, legend, and no large empty canvas. |
| `context-map-live.png` | Lateral context view with selected agent scope, reachable tools, shared infrastructure, and evidence metadata. |
| `component-{detail,findings,controls}-{dark,light}-live.png` | On-demand component drawer, exact component/scope navigation, visible source limits, and mapped controls marked not evaluated. |
| `inventory-live.png` | Unified asset-kind roll-up with explicit evidence coverage and non-empty discovered asset cards. |
| `remediation-live.png` | Fix-first remediation table with prioritized packages and framework context. |

## Manifest

Update `docs/images/product-screenshots.json` in the same PR:

- `release_version` matches `pyproject.toml`.
- `captured_at` uses UTC ISO-8601 time.
- every screenshot entry has `path`, `page`, `scope`, and `visible_version`.
- every `visible_version` matches the release version.
- each listed file exists under `docs/images/`.

## Visual Review

Before opening the PR, inspect every refreshed image:

- README desktop captures use 1440×900 and mobile captures use 390×844; capture
  the application viewport directly without cropping or editing screenshots

- no private paths, credentials, customer names, local usernames, browser chrome,
  terminal windows, or dev overlays are visible
- no empty graph, nearly empty graph, or unreadable dense graph is published as
  product evidence
- no public README, Docker Hub, or marketplace section repeats the same graph as
  separate dark/light theme screenshots unless the PR is specifically proving
  theme behavior
- graph evidence starts from an operator-readable workflow; raw expanded
  topology is acceptable only as a drilldown, not as the default public image
- text and critical UI affordances are readable at GitHub README scale
- no text, badge, code token, path, or graph label crosses its card/container
  border; long strings must wrap, truncate, or move to a details affordance
- light/dark theme claims are backed by captured evidence when the PR says so
- the image shows shipped product behavior, not roadmap copy or mock data that
  is not produced by `agent-bom`

## Verification

Run these checks before pushing:

```bash
uv run python scripts/check_release_consistency.py --release
git diff --check
```

For UI changes that alter the captured surfaces, also run the relevant UI
validation or Playwright capture command and list it in the PR body.

## PR Evidence

The PR body should include:

- exact command used to generate and push demo data
- API/UI serving mode used for capture
- refreshed asset list
- visual review summary
- validation commands and results
- linked issue or release task

Do not claim a screenshot refresh is release-ready if the manifest, visible
version, and reviewed images are not aligned.

- Graph workspace: verify the bounded package neighborhood in both themes, then the three-entity reference-lab view with the relationship inspector open. Check readable direction labels, snapshot scope and recorded evidence; do not describe the legacy asset filenames as separate layout controls.
