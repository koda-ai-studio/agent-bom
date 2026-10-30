# Prioritize fixes using recorded path coverage

With an authenticated control plane containing a retained graph snapshot:

```bash
agent-bom graph-paths fixes --scan-id <scan-id> --format json > fix-priorities.json
```

Use the existing CLI API connection options or configured API credentials.
The JSON names the exact scan, tenant and snapshot generation, followed by the
server's recommendations. In the dashboard, open that scan in **Investigation
tools → Prioritize fixes**. **Review path evidence** opens the same snapshot
and finding; **Open verification workflow** carries the source scan and finding
occurrence to the existing remediation workflow. That workflow labels the scan
as historical evidence and evaluates verification against current tenant findings.

The API is `GET /v1/graph/views/fix-first?scan_id=<scan-id>`; its
`remediation_priorities` object uses schema `graph-remediation-priorities.v1`.
The Python client exposes `graph_fix_priorities(scan_id=...)`. All surfaces
consume the same server ranking. None applies a change or marks a finding fixed.

## What the ranking means

A candidate requires an on-path asset directly linked to a finding by a
recorded `vulnerable_to` relationship. Package recommendations require a
recorded fixed version or remediation guidance; other recommendations require
recorded remediation guidance. Trace-order-only paths, explicitly unlikely paths, missing nodes and
findings without guidance do not produce recommendations.

Candidates are ranked greedily by additional critical, high, then total path
coverage. The next recommendation is scored against paths not already covered
by earlier recommendations. Critical/high counts use the directly bound finding's
severity. An exact duplicate path is counted once. Each row
shows its total and additional coverage, critical/high counts, unknown
reachability count, remaining paths outside the selections, and up to five
exact path identifiers for evidence review.

Coverage means **recorded paths touching the selected finding**. It does not
predict that applying the guidance removes those paths, establish current
effective access, or verify remediation. Alternate routes and incomplete
collection remain possible. `remediation_verified` is always `false`, and
`source_coverage` is `not_assessed`. Validate applicability and compatibility,
make the approved change, then collect fresh evidence and use the verification
workflow before claiming a fix.

## Scope, bounds and failures

The assessment uses the selected fix-first view's filters before card
pagination. It examines at most 5,000 recorded paths, 32 hops per path and
1,000 candidates, returning five recommendations. Missing nodes, truncated
graph loads and incomplete analysis remain explicit limitations. `complete`
describes the bounded recorded-path assessment, never source collection.
An empty recommendation list is not a clean security verdict.

Authentication and tenant isolation use the existing graph read boundary.
SQLite/Postgres reads pin and verify the snapshot generation; a replacement
during the read returns HTTP 409 instead of a mixed recommendation set.
Backends without generation support report that limitation. These operations
are read-only: rollback consists of returning to the existing path and finding
views, with no data migration or provider changes.
