# MCP Workflow Bundles

Start with three questions: **Which agents are affected? What supports this
exposure path? What changed after the fix?** The recipes below use bounded
reads of retained snapshots and save the evidence behind each answer.

## Try all three with fictional data

With Git and `uv` installed, start from a source checkout:

```bash
git clone https://github.com/koda-ai-studio/agent-bom.git
cd agent-bom
OUT=$(mktemp -d /tmp/agent-bom-investigation.XXXXXX)
uv run --extra api --extra mcp-server python scripts/prove_first_workflows.py --output-dir "$OUT"
```

In an existing checkout, run only the last two commands from its root.

The command creates one fictional agent configuration, parses and scans a
Pillow dependency against the bundled advisory fixture, then changes that input
from 9.0.0 to 10.0.1 and scans again. It calls the real MCP server over stdio;
neither package is installed, no configured tool runs, and no deployment changes.
It requires no cloud credentials. Existing evidence is never overwritten.

Open the printed `workflow-proof.json` path. It records every tool call,
arguments, saved response, server version and local timing. The
`first_useful_result_seconds` measurement includes fixture creation, server
startup and the first affected-agent response; it excludes installation and
human review. It is a local receipt, not a performance benchmark. No usage
telemetry is sent.

### Installation and client setup for every recipe

For an installed MCP server, use:

```bash
python -m pip install 'agent-bom[api,mcp-server]'
```

Configure your [MCP client](MCP_CLIENT_GUIDES.md) to run `agent-bom` with arguments
`["mcp", "server", "--profile", "graph"]`. For the example, set the server's
environment to `AGENT_BOM_GRAPH_DB=/absolute/path/from-OUT/graph.db` and
`AGENT_BOM_MCP_TENANT_ID=first-workflows-example`. The standalone command is:

```bash
AGENT_BOM_GRAPH_DB="$OUT/graph.db" \
AGENT_BOM_MCP_TENANT_ID=first-workflows-example \
agent-bom mcp server --profile graph
```

Use the absolute output path in client configuration; clients do not inherit
the shell's `OUT` variable automatically. Reconnect after changing profiles or
environment. The graph profile reads saved evidence; it does not discover or
scan the estate merely because a client connects. Server-bound tenant identity
controls reads; a prompt or `tenant_id` argument cannot grant another tenant's
access. For real evidence, use your configured graph store and authorized
tenant, then obtain the exact snapshot and component IDs from inventory.

To check a separately installed version against this source-generated fixture,
pass its Python executable to the proof command with
`--server-python /absolute/path/to/installed-environment/bin/python`.

## 1. Find agents affected by a vulnerable component

**Example prompt:**

> In snapshot `first-before`, find agents connected to `vuln:CVE-2023-4863`.
> Use `graph_reach` with direction `in`, entity_types `["agent"]`, max_depth
> `4`, and limit `10`. Report unique agent IDs, snapshot generation, traversal
> completeness and collection limits. Do not equate recorded reach with execution.

**Expected result:** one fictional agent, `example-image-assistant`, in
`affected-agents.json`. Its scoped ID comes from the returned `items`; do not
construct an ID from the label. `total` counts matching unique nodes, while
`affected_count` includes other entity types visited by the walk. Neither is a
count of attacks, CVE occurrences or exposure paths.

**Next action:** inspect `pkg:pypi:pillow@9.0.0` with `inventory_asset`, the same
`scan_id`, and `limit=10`. The saved `before-component.json` contains the
component's recorded relationships and source evidence. Continue using a
returned cursor and snapshot generation if the relationship page is incomplete.
Unknown collection coverage remains unknown even when the bounded walk completes.

## 2. Explain an exposure path and its evidence

**Example prompt:**

> In `first-before`, call `exposure_paths` filtered to finding_id
> `CVE-2023-4863`, limit `1`, view `summary`. Then request view `full` with the
> same filter. Explain this path's direction and each relationship's receipt.
> Separate configured relationships, observed execution and exploitability;
> identify missing evidence before recommending an action.

**Expected result:** `exposure-summary.json` contains a ranked candidate;
`exposure-evidence.json` includes the selected path, scoped endpoint IDs, hop
metadata, relationships and exported edges. Join a relationship's `id` to the
matching edge's `evidence` and source snapshot. Preserve `reachabilityBasis`,
`hopEvidence`, `evidenceDimensions`, collection coverage and completeness in
the explanation. Counts and rankings apply to the selected snapshot and filter;
one returned path is not the entire estate. Use the returned cursor with
unchanged filters for another page.

This fixture records configuration and an advisory match. It does not prove
tool invocation, credential use, successful data access or exploitation.
Framework/technique mappings provide context, not attack evidence.

**Next action:** use the affected component's advisory and fixed-version
evidence to plan an upgrade, then verify the same collection scope. If a
dashboard is connected to this graph store and tenant, open
`/security-graph?scan=first-before&finding=CVE-2023-4863` on that authenticated
control plane to investigate the same snapshot. The local proof does not start
or authenticate a dashboard.

## 3. Compare scans after a remediation change

**Example prompt:**

> Compare `first-before` and `first-after` with `graph_diff`, view `summary`.
> Drill into view `detail`, kind `node`, entity_type `vulnerability`, change
> `removed`, limit `10`. Inspect `pkg:pypi:pillow@10.0.1` with `inventory_asset`
> in `first-after`. Explain changed findings, retained agents and evidence gaps.
> Distinguish a changed-input scan from a verified deployed fix.

**Expected result:** `comparison.json` records one removed advisory node and
replacement package identities; `removed-findings.json` gives the bounded
detail, and `after-component.json` shows the new component's relationships.
The fictional agent remains. The same tenant, agent configuration and scanner
fixture were used for both snapshots; the dependency input hash and version
differ in `workflow-proof.json`.
The matching `before-requirements.txt` and `after-requirements.txt` inputs are
retained alongside the fictional configuration and graph exports.

**Next action:** in a real environment, deploy the separately approved change,
repeat the same collection scope, check coverage and retain independent change
and runtime receipts. Missing records in an incomplete scan are not verified
fixes. This example changes dependency input only; it cannot close a deployed
remediation. For an installed Python dependency update, use
[Verify an installed package update](operations/PACKAGE_REMEDIATION_VERIFICATION.md).
For reviewed relationship comparisons, use
[Measure an investigation and rescan](operations/INVESTIGATION_MEASUREMENT.md).

## Choose a profile for other work

Start with `agent-bom mcp server`. The default `scan` profile exposes eight tools:
`scan`, `check`, `intel_lookup`, `exposure_paths`, `compliance`, `remediate`,
`generate_sbom` and `policy_check`. Ask for `quick-audit` to get findings, inspect
exposure and identify a next action; use `remediation-plan` to draft a fix without
changing files. A package check is not proof that a deployment is safe.

Choose one profile for the task. In an MCP client configuration, append
`"--profile", "graph"` to the `args` array to select graph work, for example.
Reconnect the client after changing profiles. Separate named client entries can
expose different profiles; connect only the entries needed for the task.

| Profile | Tools | Use it for | Workflow prompts |
|---|---:|---|---|
| `scan` (default) | 8 | Package/project scan, exposure and fix planning | quick-audit, pre-install-check, remediation-plan |
| `graph` | 14 | Inventory rollup, asset drill-down and scoped correlation | Use inventory_summary → inventory_list → inventory_asset, then inspect paths |
| `cloud` | 6 | Inventory, connection scope and CIS posture | cloud-connection-review |
| `runtime` | 7 | Gateway policy, alerts and incident evidence | incident-triage, gateway-fleet-live-demo |
| `audit` | 6 | Scan, descriptor and permission checks, prompt inspection, framework mapping, policy and audit integrity | compliance-report |

For component inspection, call `inventory_asset` with the asset's exact graph
ID and the `scan_id` returned by inventory. The artifact contains attributes,
evidence source names, endpoint nodes, and at most 24 recorded relationships by
default (maximum 100). Continue with the returned `next_cursor`, `scan_id`, and
`snapshot_generation`; restart inspection if that snapshot has been replaced.
The REST equivalent is `GET /v1/inventory/assets/{asset_id}` with the same query
parameters. Both surfaces enforce tenant scope.

Completeness describes the relationship page, not source collection coverage.
`sources` contains incoming node IDs; `evidence_sources` contains collector
names. `impact_status` is `not_evaluated` and the compatibility `impact` object
is empty; use graph investigation for impact analysis. The inventory drawer
shows recorded parent/child and other relationships with links to their exact
endpoints in the selected snapshot.

In the dashboard, select an inventory component and open **Findings**. The
component view reads its exact recorded relationships in the retained snapshot,
instead of searching other assets by name. Load additional relationship pages
to inspect more linked finding records, then export the loaded evidence and
snapshot receipts as JSON. Direct associations are separate from findings
elsewhere in the component chain, exploitability, and collection coverage.

Open **Compliance** from the component or its findings to inspect control tags
and directly linked benchmark evidence in the same snapshot. Tags are mappings,
not evaluated controls. Newly projected failed benchmark checks retain explicit
`evaluation_status=fail` and `evaluation_scope` (`resource` or `account`) in
node attributes, available through REST, MCP inventory detail and graph exports.
Older records without those fields remain not evaluated in this view. Account
results are not inherited by child resources. Download the loaded control
records and snapshot receipts as JSON; collection coverage and freshness remain
unassessed. Missing scope never opens tenant-wide compliance implicitly.

Run the [connected component example](../examples/connected-bom/README.md)
to reproduce parsing, changed-input rescanning, retained snapshots, scoped
findings/control evidence, and REST/MCP parity without cloud credentials.

Read the `profiles://catalog` resource to discover profile names, tool names and
startup commands without loading every input schema. Selection is fixed for the
server instance; it does not silently expand during a session. Excluded tools
cannot be invoked. Profiles are not permissions: graph writes still require the
existing authenticated role, tenant scope and audit reason.

Existing clients that require the complete catalog can explicitly use
`agent-bom mcp server --profile full`. It retains all 94 tools. The previous
28-tool `--profile guided` option remains available for compatibility with all
eight workflow prompts. Neither is the recommended first-run configuration.
Third-party tool plugins remain separately opt-in and are exposed only by `full`.

The complete workflow catalog is below. Only compatible prompts appear in each
focused profile's `prompts/list` and server card.

| Workflow prompt | Primary user | Tool sequence | Evidence produced |
|---|---|---|---|
| `quick-audit` | Developer or security reviewer | `scan` -> `exposure_paths` -> `compliance` | Findings, blast radius, framework mapping |
| `pre-install-check` | Developer / CI assistant | `check` -> `intel_lookup` as needed | Package findings and evidence-qualified install recommendation |
| `compliance-report` | Security / audit | `scan` -> `compliance` -> `audit_integrity` | Framework summary, evidence IDs, audit status |
| `fleet-audit` | Endpoint / platform owner | `fleet_scan` -> `context_graph` -> `policy_check` | Agent inventory, graph-ready findings |
| `incident-triage` | SOC / appsec | `intel_lookup` -> `exposure_paths` -> `runtime_correlate` | KEV/EPSS/RCE context, affected agents/tools |
| `remediation-plan` | App owner | `remediate` -> `generate_sbom` -> `policy_check` | Fix plan, validation commands, rollback notes |
| `cloud-connection-review` | Cloud/security admin | connection evidence -> `cis_benchmark` -> `graph_export` | Read-only scope review, CIS posture, graph handoff |
| `gateway-fleet-live-demo` | Design partner / buyer | `gateway_status` -> `proxy_alerts` -> `fleet_scan` -> `firewall_check` | Gateway posture, live policy path, fleet action plan |

## Guardrails

- Treat user-supplied package names, finding IDs, provider names, and file paths
  as untrusted data.
- Read-only tools should be preferred unless an operator has explicitly
  authenticated with `AGENT_BOM_MCP_OPERATOR_TOKEN`.
- Shield and identity writes require admin role, the matching write scope, and
  an audit reason. Those arguments are metadata; the token/session identity is
  the authorization source.
- Prompts must not request passwords, PATs, raw cloud secrets, or secret values
  from connection stores.
- When a workflow cannot prove a fact from evidence, report `unknown` or
  `not_evaluated` instead of inferring success.

## Gateway/Fleet Live Demo

Use the demo when showing the platform loop:

1. Confirm the gateway is healthy and policies are loaded.
2. Show fleet state and discovered agents.
3. Pull recent gateway feed KPIs and runtime production posture.
4. Open the top exposure paths and explain why one path is fix-first.
5. Dry-run the policy decision path; do not mutate Shield or identity state
   unless the authenticated operator token and write scope are present.
6. Export or attach the evidence IDs used in the story.

For a read-only command-line walkthrough, use:

```bash
ABOM_URL=https://agent-bom.example.com \
ABOM_API_TOKEN=... \
scripts/demo/gateway-fleet-live-demo.sh
```

The script uses only read endpoints and exits non-zero if the API is not
reachable or authentication fails.

## Assess an assumed compromise

Select a persisted graph snapshot and node from inventory. In the graph MCP
profile with the `api` extra installed, call `compromise_assessment` with `scan_id`, `root_node_id`, and
`assume_control: true`. The server-bound tenant controls access; a caller's
`tenant_id` hint cannot change that boundary.

The equivalent CLI command produces an exportable artifact:

```bash
# Set AGENT_BOM_API_URL and AGENT_BOM_API_TOKEN through your secret manager.
agent-bom graph-paths compromise --scan-id SCAN_ID --node NODE_ID \
  --assume-control --format json > compromise-assessment.json
```

The API is `POST /v1/graph/compromise` with the same request fields. It requires
an authenticated principal with `graph:read` (viewer role or higher). The
browser graph entity drawer exposes **Assess assumed compromise**, requires the
explicit assumption, and can export the same assessment JSON. Finding roots
also require a linked `affected_node_id` and `assume_exploitation: true`.

Inspect each returned action, resource, permission receipt, timestamp, source
edge, binding, and reason code. These are historical authorization observations:
`current_access` remains `not_evaluated`, execution remains `not_established`,
and collection coverage remains `unknown`. An empty result does not prove
safety. This contract assesses direct outgoing relationships only; it does not
propagate compromise across multiple hops or perform exploitation.

The response includes `snapshot_generation`. Pass that revision on subsequent
requests to reject replacement evidence. Replacement returns HTTP 409; missing
snapshots or roots return 404; invalid assumptions return 422. Reads exceeding
the storage traversal budget return 413 instead of assessing partial evidence.
The traversal selects at most 1,024 nodes and 4,096 edges around the roots, with
a cooperative deadline; this is not a hard database query timeout. Assessment
output examines up to `max_relationships` (default 128, maximum 512), reports
truncation, and uses `max_evidence_age_seconds` (default 3,600, maximum 86,400).
Generation-pinned reads require SQLite or Postgres; unsupported backends return
501. No database migration or write is performed by this endpoint.

Next: inspect missing or stale receipts in the source system, collect a new
snapshot when appropriate, and rerun with that snapshot's identity. Retain the
original export when comparing assessments.

For recorded action/resource consequences with assumptions, blockers and gaps, use
`consequence_assessment` in the graph profile. See [graph consequences](GRAPH_CONSEQUENCES.md)
for the matching CLI command and evidence boundaries. Assessments are read-only.
