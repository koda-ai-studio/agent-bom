# Investigate graph consequences

The experimental consequence assessment reports recorded action/resource
permissions, stopping controls, and missing evidence under an explicit starting
condition. It is read-only and requires authenticated `graph:read` access.

## First command → artifact → next step

Select a persisted snapshot and an exact agent or principal from graph inventory.
Use your configured API credentials; do not paste secrets into the command.

```bash
agent-bom graph-paths consequences --scan-id SCAN_ID --node PRINCIPAL_NODE_ID \
  --mode assumed_compromise --assume-control > consequences.json
```

`consequences.json` contains one pinned snapshot generation, the evaluated
assumption and time, ordered paths, source binding references, separate supported,
conditional, blocked and unknown counts, and collection gaps. Inspect a path's
exact action and resource before deciding which evidence to collect next.

For a vulnerability, choose a component linked by `vulnerable_to` or `affects`:

```bash
agent-bom graph-paths consequences --scan-id SCAN_ID --node VULNERABILITY_NODE_ID \
  --mode vulnerability --affected-node PACKAGE_NODE_ID > prerequisites.json
```

Local exploitability currently has no qualified occurrence-specific collector.
This investigation retains the exact affected inventory/version receipts and
advisory requirements separately, then reports missing deployment configuration,
entry point and exploitation prerequisites. It stops before
assuming control. CVSS, EPSS, KEV and dependency reachability do not fill that gap.

## Evidence boundaries

- Azure/GCP normalized authorization decisions reuse the existing evaluator.
  Allowed receipts stay on permission edges. Denials and indeterminate receipts
  are persisted on their exact principal as `authorization_boundaries`, including
  action, resource, collection time, denial binding IDs and missing-source reasons.
  These records do not create access edges. Storage uses existing node/edge JSON;
  old snapshots remain readable and missing receipts remain unknown.
- Exact provider node mappings preserve typed native identities. Credential slot
  names, agent labels, shared servers and correlation links cannot transfer
  authority. Reading a resource never grants control of it.
- Multi-hop session evaluation is a foundation with a strict, scoped
  `graph.session-binding.v1` contract. Current config declarations and governance
  registrations do not produce qualified session receipts. They therefore stop
  at an explicit missing-session boundary. Fixture tests do not establish live
  provider session coverage or independently observed effects.
- Categories use exact provider action names. Unrecognized actions remain
  unclassified. A tool named `create_pull_request` does not establish repository,
  merge or deployment permissions. Resource sensitivity and business loss are
  never invented.
- Limits cover depth, states, results, store nodes/edges and elapsed time.
  Incomplete reads are explicit; counts are lower bounds. A complete traversal
  describes the collected graph, not complete estate coverage. Negative decisions
  do not prove that all alternate paths are blocked.

## Equivalent surfaces

`POST /v1/graph/consequences` accepts the same mode, root, affected occurrence and
bounds. Supply `snapshot_generation` to require a previously returned revision.
The API rejects changed revisions, including a replacement during the read.
The graph MCP profile exposes `consequence_assessment` with a strict nested
`request`, `scan_id` and optional revision. The server-bound tenant is authoritative.
Python `AgentBomClient.consequence_assessment` and TypeScript
`AgentBomClient.consequenceAssessment` return the same server-computed receipt.

The investigation drawer offers a linked-occurrence selector and opens a wide
consequence workspace. Selecting an action focuses its recorded identity/resource
path and stopping control. Receipt details, prerequisite checks, collection steps
and JSON download share the same assessment. Selection changes cancel old
requests. The exported object is the displayed assessment. The direct-only
`POST /v1/graph/compromise`, `compromise_assessment` MCP tool and `graph-paths
compromise` command retain their v1 behavior.

This additive workflow can be rolled back independently of existing graph reads;
retain collected snapshots and exported receipts. No proposal executes a provider
write, revokes credentials, proves exploitation, or verifies incident containment.
SARIF and SBOM formats retain their finding and inventory semantics; use the
separate JSON assessment for consequences.

## Contract maintenance

Regenerate OpenAPI with `python scripts/export_openapi.py`, frontend types with
`npm --prefix ui run codegen:api-schema`, and the focused TypeScript SDK contract
with `node ui/scripts/codegen-consequence-sdk.mjs`. Use its `--check` mode to detect
SDK drift. Run `make preflight` before delivery.

## Containment permissions and service impact

Discovery connections are read-only. A successful connection or an access finding
never grants the control plane permission to change that provider. This assessment
cannot stop an AWS workload, revoke its credentials, or enforce a modeled fix.
The graph links to a separate fleet review instead of selecting a containment
subject by display name. Names can collide across accounts and environments.

The existing fleet quarantine requires `policy_write` and an exact tenant-scoped
fleet agent ID. It records a lifecycle change and a gateway deny policy. Only calls
routed through that enforcement point under the authenticated fleet identity are
in scope; direct provider calls and other credentials or connections remain outside
it. Policy persistence is not confirmation that every runtime has applied it.
Releasing the fleet agent disables its quarantine policy; it cannot recover work
already interrupted or undo prior effects.

For example, AWS AgentCore exposes `StopRuntimeSession`, requiring the runtime ARN,
active session ID and `bedrock-agentcore:StopRuntimeSession`. This interrupts that
session and its streams; it does not establish complete containment or prevent new
sessions. Agent-bom does not implement this provider action. See the
[AWS session stop documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-stop-session.html).
Revoking older IAM role sessions can affect other workloads sharing the role; see
[AWS role session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html).

Before an operator executes a proposed restriction, review:

- The evidence, uncertainty, affected agent/session and exact provider resource.
- Required write permissions, enforcement point and paths outside its coverage.
- Shared roles, service dependencies, active work and expected interruption.
- A narrower restriction where supported, human approval and rollback limitations.
- Fresh evidence of the resulting access state and any remaining paths.

A vulnerable package or a name-based trace association alone is insufficient to
justify quarantine. Unknown business impact remains unknown. No automatic
quarantine or zero-disruption guarantee is provided by this investigation.


## Explain a recorded relationship

Hover or keyboard-focus an entity to reveal secondary counts and metadata; select it to open the evidence inspector. Counts cover linked entities in the loaded graph data and may be incomplete.

Select an edge in the graph to open **Relationship details → Why linked**. The
explanation distinguishes inventory use, available tools, dependencies and
vulnerability findings from runtime execution. Recorded source, basis, mapping
method and package/version fields appear when supplied by the selected edge;
the relationship name does not fill missing source evidence.

In an entity's recorded relationship list, expand **Why linked** for the same
explanation and its **Recorded evidence** disclosure. A conservative
server-scoped tool-impact mapping does not establish an exact package-to-tool
call path. Inspect the finding and package/version receipt before choosing a
fix; a graph connection alone does not prove exploitation or successful access.

The inspector and recorded relationship rows also show **Evidence type**,
**Source observed at**, **Graph last seen**, and **Graph traversal** without
opening raw evidence. Evidence types come from explicit receipt markers;
unrecognized markers remain unclassified and absent markers stay unrecorded.
Mixed markers remain visible as mixed evidence rather than being promoted to
runtime observation. Original tier and basis fields stay in **Why linked**.

**Source observed at** uses the receipt's `observed_at` field. A supplied
`timestamp` is shown separately as **Receipt timestamp**. Neither is filled from
the graph's `first_seen` or `last_seen`: those fields can reflect graph-record
creation. A timestamp is not a freshness guarantee, and traversal eligibility
is not verification of runtime reachability. Use the recorded source and snapshot
to collect fresh evidence before making an access or remediation decision.
