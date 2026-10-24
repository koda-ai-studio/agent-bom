# Governance

agent-bom is an Apache-2.0 project that wants more people with merge rights,
not fewer. This page says how decisions are made and how a contributor becomes
a maintainer. Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Roles

| Role | What you can do | How you get it |
|---|---|---|
| **Contributor** | Open issues and PRs, review, answer questions | Anyone, from your first issue or PR |
| **Triager** | Label, deduplicate and route issues; mark `good first issue` | 3+ helpful triage comments or merged PRs; ask a maintainer |
| **Reviewer** | Approve PRs in an area you know; listed in `CODEOWNERS` for it | 5+ merged non-trivial PRs in one area, plus reviews other contributors found useful |
| **Maintainer** | Merge, cut releases, set direction, grant roles | Sustained reviewer work for about 3 months; nominated by a maintainer, no objection from the others within a week |

The thresholds are guides, not a points system. Quality and reliability count
for more than volume: a contributor who lands three careful fixes with tests
and reproductions is closer to reviewer than one who lands ten typo fixes.

### Asking for a role

Open an issue titled `Role request: <role> for @you`, link the PRs, reviews or
triage that show the work, and name the area. A maintainer replies within a
week. A "not yet" comes with what is missing.

## How decisions are made

- **Day-to-day changes** go through PR review. One maintainer or area reviewer
  approval merges a change; CODEOWNERS paths need a maintainer.
- **Larger changes** (new top-level modules, new deployment targets, breaking
  API or CLI changes, new data leaving the user's machine) start as an issue
  with the proposal, and merge after maintainers agree on it in that issue.
- **Disagreement** is settled in the issue by the maintainers. If they cannot
  agree, the project lead (@msaad00) decides and writes down why.
- **Security reports** follow [SECURITY.md](SECURITY.md) and stay private until
  a fix ships.

## Standards every role keeps

- Findings must be accurate. Do not merge a change that makes the scanner,
  graph or exports claim something the evidence does not show.
- Nothing leaves the user's machine without being documented in
  [PERMISSIONS.md](docs/PERMISSIONS.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Stepping back

Roles are not permanent obligations. A maintainer or reviewer who has been
inactive for 6 months moves to emeritus in MAINTAINERS.md and can return by
asking. Emeritus maintainers keep their credit.
