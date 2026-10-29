# Graph Contract

This is the single page that tells operators, auditors, and regulators what agent-bom's graph promises and what it does not. Guarantees that previously lived scattered across the README, [ARCHITECTURE.md](../ARCHITECTURE.md), and [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) consolidate here.

The graph subsystem has one source of truth in code: enums in `src/agent_bom/graph/types.py`, the report builder in `src/agent_bom/graph/builder.py`, and the projections in `src/agent_bom/graph/`. Every name on this page maps 1:1 to those files.

The generated [data model reference](DATA_MODEL.md) lists every entity, relationship, evidence tier and normalization table from that code.

---

## Base paths and derived investigation paths

SQLite and Postgres retain two path populations for each tenant and scan:

- `attack_paths` preserves the paths supplied by the base graph, normally the
  fusion analyzer's output. Full-graph loading and base-path traversal read it.
- `graph_attack_paths` is a versioned investigation projection, including
  derived governance, credential and component paths, hop evidence, and indexed
  queue ordering and vendor filters. Snapshot path pages read this projection.

These populations are not additive. A graph can have no base paths and still
produce investigation paths. Paths with the same hop chain can have different
reachability, risk or evidence after derivation. Equal counts do not prove the
payloads are interchangeable: the showcase demo intentionally supplies already
projected base paths, while scanner graphs may require further derivation.

`GET /v1/graph/attack-paths` and the MCP `exposure_paths` tool share the same
queue selection. Their `count_metadata.path_population` is
`derived_investigation_paths` for a current snapshot projection or read-time
derivation, and `base_graph_paths` for the persisted base fallback. Counts
describe the selected population; never add both tables to compute a total.
The existing `source`, completeness, snapshot and generation fields retain
their scope and continuation semantics.

Keep base evidence intact when refreshing derived paths. A shared-payload
storage design would need to preserve distinct payloads, duplicate path
occurrences, tenant/scan identity, derivation-version fallback and atomic
snapshot replacement in both backends. Dropping `path_json` or replacing the
base table with a view over derived rows would lose that distinction. The
current separate projection avoids a join on indexed queue reads in exchange
for additional storage.

## Current estate and historical scans

An omitted `scan_id` on inventory and graph reads selects the current tenant
estate. A complete rescan replaces only its own target. Incomplete observations
retain prior evidence for that target; other targets and observed clean assets
remain visible. Explicit historical scan IDs keep their original scope. A graph read whose
`scan_id` names no snapshot of the caller's tenant returns 404, never an empty
page marked complete; MCP graph tools return `AGENTBOM_MCP_NOT_FOUND_RESOURCE`.

```bash
curl -H "X-API-Key: $AGENT_BOM_API_KEY" \
  "$AGENT_BOM_API_URL/v1/inventory/assets?limit=25" > inventory.json
```

Inspect `evidence_scope`, `scan_id` and `snapshot_generation` in the response.
A `current-estate:` identifier describes a derived set of source revisions, not
one scan. Keep the returned cursor and generation together while paging; restart
a page after a generation conflict. Select a recorded scan ID to investigate
historical evidence. REST, MCP inventory tools and the dashboard share this scope.
While the demo estate is seeding (`/health` reports `demo_seed: pending`), every
unpinned current-estate read returns 503 `current_estate_seeding` with
`Retry-After`: `/v1/graph` and its sibling graph reads (attack and exposure
paths, search, agents, rollup, node reads, query, deploy gate), and
`/v1/inventory/assets` and `/v1/inventory/summary`. MCP graph tools served by the same process return
`AGENTBOM_MCP_UPSTREAM_UNAVAILABLE` with `details.reason: current_estate_seeding`
and `details.retry_after_seconds`. None answers with a partial or empty estate
marked complete. Reads pinned to a recorded `scan_id` are served.

Current projections use a private rebuildable query cache. They do not add scans
to history or modify source observations. Collection gaps remain visible and
query completeness does not establish complete collection. Finding severity and
recorded connections do not by themselves establish assessed risk or execution.


## Agent inventory lifecycle view

Open **Agents → an agent → Lifecycle graph** to inspect its configured inventory.
The initial view shows server connections. Select **Packages and advisories** or
**Tools and credentials**, then choose a server, to inspect a smaller neighborhood.
Counts describe unique entities across the supplied agent inventory; the canvas
states how many loaded entities are shown. **Export** saves the complete response,
including canonical graph IDs and relationship receipts.

`GET /v1/agents/{agent_name}/lifecycle` uses the shared inventory graph projection.
The legacy `nodes`/`edges` envelope remains available, with each edge's canonical
receipt in `data`; `graph` carries the shared graph representation. Shared packages
retain every server relationship, ecosystems remain distinct, credential slots
remain server scoped, and tools are not silently limited to ten. These are
configured relationships, not proof of execution, exploitation or effective access.
This derived view does not invent a persisted scan ID. Existing endpoint
authorization and tenant selection apply.

## 1. Coverage

### Entity types

`EntityType` in `src/agent_bom/graph/types.py` is a closed enum. Every node
carries one of its values. The generated [entity reference](data-model/entities.md)
lists each type, its emitter modules and observed ID formats. Production emitters
are listed separately from demo fixtures; vocabulary alone does not prove emission.

### Conflicting security observations

When sources identify the same asset but disagree about a boolean exposure or
privilege flag, the merged projection retains an explicit positive risk value.
It does not establish current effective access or successful execution. Review
`attributes.identity.conflicts` (single-build canonicalization) or
`attributes.correlation.conflicts` (snapshot correlation) for the competing
normalized values, sources, snapshot IDs and node IDs. Unknown values remain
unknown. Original snapshots are unchanged.

Canonicalization reports `conflicting_attributes` and, for security flags,
`conflicting_security_assertions` with limited analysis status. Repeated merges
retain the original receipts instead of attributing a merged value to every
source. Ordinary metadata still follows the existing precedence rules. Collect
fresh evidence and review its scope before treating an earlier positive claim
as resolved.

### Discovered Okta identities

New graph projections record canonical keys for Okta organizations and their
discovered non-human identities when the provider tenant origin is valid and
normalized. Repeated snapshots correlate on organization, identity kind and
native ID; a display-name change does not create a new identity. Equal native
IDs in different organizations or different identity kinds remain separate.
Correlation retains both source observation receipts and the recorded organization
membership. It does not infer tool-access grants from scope names.

Missing, invalid or unnormalized imported origins remain snapshot scoped.
Historical snapshots without these keys are unchanged; collect a new snapshot
to record the qualified identity fields.

### Canonical identity version 3

New scan exports declare `canonical_id_schema_version: "3"`. Structured,
case-preserving components distinguish embedded separators, empty values and
case-sensitive resource identifiers. Agent graph IDs include source or config
scope; exports retain the graph aliases calculated before config-path redaction.
Two same-named agents in different config files remain separate occurrences.

MCP instance IDs retain the complete executable, argv element boundaries,
working directory and configured environment in an opaque fingerprint. URL
paths, parameters and query routing remain significant. A registry artifact
is metadata, not proof of a shared endpoint or process. Configured stdio
launches stay scoped to their declaring agent; matching recipes do not prove
one runtime process. Remote endpoint nodes can be shared, while every agent
retains its own relationship. Earlier recipe/name IDs remain explicit alias
candidates and are not resolved when multiple current instances claim them. A `SHARES_SERVER`
correlation requires the same resolved server node, never an equal display name
or launch recipe. It is non-traversable and does not establish delegation,
execution or effective access. Pairwise `SHARES_SERVER` edges are emitted only
for groups of up to 16 agents; every shared server node records
`shared_agent_count` and `shares_server_pairwise`, so a larger group is read from
the server's `uses` edges instead of a quadratic agent mesh.

An upgrade does not rewrite stored snapshots. SQLite and Postgres persist new
canonical-ID receipts and read historical rows with their original version-2
identity. Exported IDs already recorded in imported graphs are retained. A
rescan creates version-3 IDs; consumers comparing new exports with older ones
must use the declared identity version and explicit aliases, not labels. Fleet
migration retains an existing approval only when its source/device or exact
local type, name and config scope agrees. Ambiguous matches remain separate.

Aliases resolve only when one node owns the alias within the selected tenant
and snapshot. An omitted snapshot on the store alias lookup uses its latest scan;
an older binding cannot revive an alias that is now ambiguous. Trace edges may
bind an explicit recorded alias and retain `identity_bindings` with the reported
reference and resolved node. A matching display name remains a candidate and
does not become an execution edge.

Training datasets and serving configurations without a stable native identifier
retain separate source observations. A shared label, image or unqualified model
suffix does not establish identity. Serving-configuration nodes do not assert a
running container; label-only runtime targets do not assert inventory identity.
Select the node receipt to inspect its source and scope before comparing it with
another observation.

### Cloud identity correlation and governance

Azure role assignments join collected managed identities and service principals
by native directory object ID. GCP service accounts also accept the collected
email and typed `serviceAccount:` member form. Display names, incompatible
identity types and ambiguous aliases never select an existing principal for an
authorization grant. An unresolved binding retains a separate native-ID node;
it does not inherit another identity's inventory or usage.

Governance covers Azure service principals as well as managed identities, AWS
roles and GCP service accounts. For cloud inventory, missing ownership or usage
telemetry remains unknown: it cannot establish an orphan, dormancy or unused
permission. Explicit evidence can produce those findings. AWS Access Advisor
right-sizing findings retain their own provenance and are not duplicated by
NHI over-grant findings. Configured grants remain distinct from effective
permissions, observed execution and successful access.

Rescan or rebuild existing snapshots to apply corrected identity joins and
verdicts. Stored historical snapshots are preserved; rolling back the binary
restores the previous derivation behavior.

### Edge kinds

`RelationshipType` in `src/agent_bom/graph/types.py` is a closed enum. The
generated [relationship reference](data-model/relationships.md) lists allowed
source/target pairs, evidence requirements, traversal semantics and emitter
modules. `/v1/graph/schema` identifies verified production emitters and reserved
vocabulary. Reserved kinds remain readable in historical and demo snapshots.

Edges carry `weight` and `evidence` (a metadata dict). Bidirectional edges (`shares_server`, `correlates_with`) are stored once but traversed both ways.

Every relationship has one `RelationshipSpec` in `agent_bom.graph.relationship_specs`: its traversal class, the exact `(source, target)` entity pairs it may connect, direction, default traversability and required evidence keys. `GET /v1/graph/schema` publishes the registry (`traversal_class`, `allowed_pairs`, `required_evidence`). Every edge's `evidence` names its collector in `source` and the kind of claim in `tier` (`modeled_infrastructure`, `static_scan`, `recorded`, `runtime_observed`, `derived`; edges rehydrated from snapshots written before the envelope carry `legacy_unrecorded`). `AGENT_BOM_GRAPH_CONTRACT` sets what a violation does: `warn` (default) keeps the edge and counts it in `analysis_status.relationship_contract`, `enforce` drops an edge whose pair is not allowed, and `strict` raises.

### Provider authorization receipts

Azure/GCP authorization evaluation emits `can_access` edges only for an explicit
`allow` result. Each `evidence.authorization_decisions` record
keeps the evaluated principal, concrete action, resource, decision, provider,
matched binding IDs, and source observation time together. Multiple allowed
actions on the same edge retain separate records through graph aggregation,
SQLite/Postgres persistence, and the graph API. Top-level compatibility fields
such as `action` are omitted when the records disagree; the union of binding
IDs does not authorize every action under every binding.

Identity-attachment actions (`iam.serviceAccounts.actAs` and
`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) retain their
allowed-action receipts on a **nontraversable** `can_access` edge to the target
identity. These permissions alone do not establish an impersonated session or
inherit the target's access. The edge records `authority_effect=identity_attachment`
and the missing workload-control, attachment, and credential-access context;
analysis is `limited` with `identity_attachment_requires_workload_context`.
See [Google's service-account permission semantics](https://docs.cloud.google.com/iam/docs/service-account-permissions)
and [Azure's managed-identity assignment prerequisites](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-configure-managed-identities).

Rebuild or rescan older snapshots that contain `assumes` edges derived from
these attachment permissions. Historical snapshots are not rewritten on read;
rolling back to an older binary restores the earlier derivation behavior.

These receipts describe the evaluator's result for the collected snapshot.
They do not establish that an action executed, that data was affected, or that
the grant is still valid now. Conditional, denied, stale, and incomplete inputs
remain subject to the evaluator's fail-closed behavior. This receipt list
currently retains allowed decisions, not the complete policy evaluation trace.
Derived permission overlays and specialized path responses must not be assumed
to expose this action detail merely because the source edge contains it.

Existing snapshots may contain only a single legacy action receipt. Reading or
merging that record cannot recover actions previously discarded; collect fresh
authorization evidence and rebuild the snapshot to obtain the full retained
set of evaluated allowed actions. Missing legacy principal or observation fields
remain unknown.

### AWS policy conditions

AWS identity-policy evaluation retains supported string/ARN set qualifiers:
`ForAllValues` requires each supplied request value to match the policy;
`ForAnyValue` requires one. Negated operators compare each request value against
all policy values before applying the set qualifier. See the
[AWS condition-operator reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).
Missing request context remains unknown, including for `IfExists` and `Null`:
this contract does not carry proof that a key was absent from a complete AWS
request. An explicitly supplied empty value set is distinct. Malformed conditions make their policy incomplete instead of
becoming unconditional grants. A valid explicit deny retains precedence.

This evaluator does not establish a complete AWS effective-permission verdict:
unsupported operators, missing session context, permissions boundaries, SCPs
and resource policies need their own evidence. Rebuild snapshots after changing
policy evidence or upgrading the evaluator; existing derived snapshots are not
rewritten by a read request.

### Derived permission witnesses

Newly built `has_permission` edges include `evidence.permission_derivation`.
Its ordered `source_edge_ids` reference the actual access, group-membership, or
assume/inheritance relationships in the same `source_scan_id`. The
`grant_edge_id` identifies the original access edge and its action receipts;
`grant_principal_id` remains the original role, group, or direct principal.
Inheriting that graph connection does not relabel the source's policy decision
as a directly evaluated grant for the requesting identity.

The overlay retains one deterministic shortest witness for each grant and
access class, with at most 16 witnesses per derived edge and six principal
transfer hops. It does not enumerate every alternate route or reevaluate policy
provider policy conditions or session restrictions. A witness cap marks the
edge's derivation `truncated`; an unvisited frontier at the depth limit or a
witness cap marks the snapshot analysis `limited`. Cycles alone do not mark a
walk incomplete. Consumers must resolve source references within the same
tenant and snapshot, and show an evidence gap when a source edge is unavailable
in a bounded response. Old snapshots require rebuilding to gain these witnesses.

New permission derivation excludes source edges that are deleted, not yet valid,
expired, or have invalid validity windows. It evaluates at UTC now by default;
a historical build must pass its evaluation time explicitly. Each witness uses
the intersection of its source windows; overlapping alternate witnesses may
extend the resulting interval. This preserves recorded graph validity, not a
fresh provider authorization decision. Existing snapshots and derived edges are
not retroactively rewritten; rebuild them to apply these checks.

### Managed-identity governance scope

The live governance overlay connects a managed identity to an exact agent node
ID when available, otherwise to one unambiguous agent label. Duplicate labels
remain unlinked. This is a registered binding, not evidence of an authenticated
session. Expired or invalid identities do not acquire traversable tool scope;
JIT scope requires a live identity and an active grant within its recorded time
window. Pending, revoked, future, or expired grants do not establish access.

A matching unconditional deny leaves a context-only scope edge with
`authorization_state=explicit_deny`. Applicable conditional policies require
request context and use `context_required`; unavailable or capped policy
collection uses `policy_evidence_unavailable`. These edges are non-traversable
and do not generate governance access paths. Policy IDs and required context
survive edge serialization. `recorded_scope` means the collected scope has no
such unresolved policy guard; it does not prove a successful tool call or data
access. Runtime enforcement is unchanged by this graph qualification.

---

## Evidence truth dimensions

The versioned `SecurityDimensions` contract keeps six questions independent:

| Dimension | Question | Value when not assessed |
|---|---|---|
| Exposure | Is there an entry point, credential, or tool exposure? | `status=unavailable`; no inferred `false` |
| Reachability | Is a directed, traversable path supported by evidence? | `verdict=null`; never copied from exposure |
| Exploitability | Do the vulnerability and execution conditions permit exploitation? | `verdict=null`; never copied from risk |
| Likelihood | What bounded probability model applies as of a stated time? | `probability=null`; never a risk score |
| Impact | Which technical or business assets could be affected? | empty facts with an explicit reason code |
| Risk | What versioned method combines named input dimensions? | `score=null`; never an unavailable zero |

Each asserted fact references an `EvidenceProvenance` receipt. Its `basis`
(`observed`, `runtime_observed`, `inferred`, or `modeled`) is separate from its
collection `status` (`complete`, `partial`, `unavailable`, or `failed`).
Freshness is evaluated against an explicit `evaluated_at` timestamp and validity
window; process time is not consulted during model validation.

`EvidenceCompletenessLedger` records collection, normalization, catalog lookup,
persistence, graph-join, and analysis coverage by component. An empty ledger is
`unavailable`, any relevant failed entry makes it `failed`, and any other
relevant incomplete entry makes it `partial`. Counts and reason codes describe
only what the producing component reported; they do not fabricate a clean or
complete state.

These contracts are additive foundations. Existing finding, graph, and endpoint
payloads retain their current serialization until their producers can populate
every field honestly and their migrations are independently tested.

### Graph node score assessment

Graph nodes retain the numeric `risk_score` field for compatibility. Interpret
it with the additive `risk_assessment` object: `status`, `basis`, and `scope`.
An assessed score names the calculation and the evidence scope it covers.
An absent or invalid assessment is `not_assessed`, even when the legacy numeric
field is zero or positive. A genuinely assessed zero must have explicit
assessment metadata; an empty inventory or an absence of findings is insufficient.

Node inspection displays **Not assessed** when that metadata is unavailable.
Existing snapshots without it remain unassessed until rebuilt by a producer
that records a calculation. This does not remove their findings or recorded
relationships. A node score describes only its named scope; it does not prove
complete collection, exploitability, or an observed attack. Exposure-path
scores and finding scores keep their separate contracts.

Score merges retain the winning score's own assessment. A different producer's
basis must never be attached to that score merely because node attributes were
combined. Persistence retains the assessment alongside node attributes without
requiring legacy numeric consumers to migrate immediately.

---

## 2. Accuracy guarantees

agent-bom's graph is an analytical artifact derived from inventory, findings and recorded runtime evidence. The guarantees below are the ones we will defend in an audit.

- **Stable topology for the same report and scope.** `build_unified_graph_from_report()` in `src/agent_bom/graph/builder.py` projects report evidence into `UnifiedGraph`. Rebuilding the same scoped report preserves node IDs and relationship keys; see `tests/graph/test_finding_type_matrix.py`.
- **Stored evidence remains readable.** Graph snapshots retain nodes, edges and their recorded evidence. Readers classify missing evidence tiers as `legacy_unrecorded`; they do not infer a canonical tier from arbitrary text or rewrite the stored receipt. The generated [entity](data-model/entities.md) and [relationship](data-model/relationships.md) references document the current vocabulary.
- **Framework tags from canonical sources only.** Every framework tag attached to a vulnerability node comes from CISA KEV, OSV, NVD, EPSS, MITRE ATLAS, or MITRE ATT&CK. The bundled canonical metadata lives in `src/agent_bom/compliance_coverage.py`. agent-bom never invents a framework label, never derives one from heuristics, and never re-tags advisories from secondary aggregators.
- **No cross-tenant leakage.** Every `UnifiedGraph` carries a `tenant_id` (`src/agent_bom/graph/container.py`). Persistence enforces row-level security in Postgres, scoped by tenant, on every read and write path. A query for tenant A's graph cannot return tenant B's nodes or edges, regardless of API surface.
- **Untrusted external metadata is fenced.** Tool descriptions ingested from MCP `tools/list` are passed through `_untrusted_metadata_text()` (`context_graph.py`), control characters are stripped, length is bounded, and the field is marked `description_trust = "untrusted_external_mcp_metadata"`. Downstream consumers must treat that field as data, never as a label or instruction.
- **CIS check results agree with the graph.** A failed CIS control is one node (`misconfig:<benchmark section>:<check id>`) with an `affects` edge to each failing resource; an unevaluable one is a `CIS_ERROR` finding node. When the current graph holds CIS results for a cloud, `/v1/cis/checks` and the compliance scorecard's CIS Foundations line take that cloud's failing checks and their resources from the graph, so resource ids are graph node ids and `resource_finding_ids` names the finding recorded on each (`src/agent_bom/api/cis_graph_checks.py`). Stored benchmark rows still supply recorded passes, not-applicable results and remediation. A check is `pass` only when a scan recorded a passing result: a stored failure the current graph no longer holds, or a row with no recognised status, is `not_evaluated`, which is never counted as a pass and is excluded from the score's evaluated denominator. A read pinned to a historical `scan_id`, or a graph read that hit its node budget, keeps the stored rows unchanged. The signed compliance report and export pack state the stored rows of the one job snapshot they sign, so they never mix in a second evidence read.
- **Alternative graph backends must preserve this contract first.** SQLite and Postgres are the shipped graph persistence backends today. Any future backend, including the proposed Neptune lane, must preserve stable IDs, tenant predicates, snapshot semantics, bounded traversal, audit behavior, and explicit unsupported-operation errors before it can be documented as supported.

---

### Snowflake historical access receipts

Snowflake ACCESS_HISTORY observations collapse into one `ACCESSED` edge per user
and object while retaining distinct `access_receipts`. Each receipt keeps its
query ID/time, recorded query role (empty when unavailable), account, object,
columns, base objects and source array. A query that reads and writes the same
object retains both observations. `READ` and `WRITE` describe the source arrays;
they do not infer a SELECT/INSERT/UPDATE statement, current permission, or rows
changed. See [Snowflake ACCESS_HISTORY](https://docs.snowflake.com/en/sql-reference/account-usage/access_history).

Graph JSON and persisted edge evidence retain these records without combining
one query's role with another query's action. Historical access does not establish
an exact agent/session binding or current authorization; data impact remains
unknown. Collection is bounded by the configured lookback and the collector's
1,000-query limit, and source visibility/latency still apply.

## 3. Scaling boundaries

`GET /v1/graph/rollup` returns `aggregate_count_metadata` for roll-up and
drill-down views. Each card's descendant count is unique within that scope;
shared assets can belong to several scopes. `distinct_descendants` counts
unique matching descendants across returned entries, while
`descendant_memberships` is the sum of their descendant counts.
`shared_descendants`, `extra_memberships`, and `additive` identify overlap.
These counts exclude each entry itself, apply the same filters as the cards,
and describe the returned level rather than the whole estate.
`source_truncated` and `reason` preserve an incomplete source's limits.
The graph shows a compact overlap explanation when memberships exceed unique
descendants. Missing metadata in older responses does not establish disjoint
scopes.

The graph renderer ships deterministic focused and expanded modes. Operators can override per-tenant; defaults match the table below.

| Mode / size | Default behaviour | Why |
|---|---|---|
| Relevant paths default | 2-hop neighbourhood, 50-node page size, high-severity vulnerable scope, sibling fan-outs of 5+ collapsed into expandable cluster pills. | Starts every investigation readable, even on dense self-scans. |
| Ranked path queue | Persisted paths load independently from full-estate fix guidance; the response includes only consecutive path edges. Direct neighbors load on demand with a 12-node fan-out cap. | Produces a fast, evidence-minimal first view without hiding broader topology or implying unrelated edges prove the selected path. |
| Expanded mode | 3-hop neighbourhood, 250-node page size, sibling fan-outs of 20+ collapsed. | Lets operators widen context deliberately without turning the first view into a whole-tenant canvas. |
| Zoomed out | Level-of-detail renderer swaps detail cards for summary cards and cluster bubbles below the zoom thresholds. | Dense snapshots stay navigable instead of turning into unreadable labels. |
| Large overview | Visible pages at or above 500 nodes or 1,200 edges switch from React Flow to a limited 2D canvas overview. The overview draws up to 3,000 high-signal nodes and 6,000 high-signal edges; search, filters, selected-node detail, and reachability drill-ins remain server-backed. | Keeps broad estate pages from blanking or stalling while preserving React Flow for bounded investigations. |

Operators reaching large-snapshot scale should pivot to scoped queries, security-graph attack paths, the blast-radius drilldown, or the snapshot + page + search workflow described in `site-docs/deployment/performance-and-sizing.md`. The large overview is intentionally not a full React Flow replacement: it supports pan, zoom, node selection, and high-level topology, but not node cards, minimap, or path highlighting. The graph is designed for investigation, not for "render the whole tenant in one canvas."

---

## 4. What we don't promise

These are the explicit non-promises. Reading them is how regulators understand the boundary of the contract.

- **No ML inference.** There is no model on the graph build path. Nodes and edges are deterministic functions of the inventory and the canonical advisory feeds. We do not predict edges, infer relationships from embeddings, or assign risk via a learned model.
- **No causality without explicit traces.** The static graph encodes correlation, not causation. `shares_server` and `shares_cred` mean "two agents reference the same name," not "agent A caused agent B to be compromised." Causal claims require runtime traces emitted by the proxy / gateway (`invoked`, `accessed`, `delegated_to`); without those, a path through the static graph is a *reachability* claim, not a *causality* claim.
- **No real-time updates without proxy or gateway runtime.** The static graph is a snapshot built from the last scan. New tool calls, new credential exposure during a session, and live agent-to-agent delegation are not visible until the proxy or gateway runtime ships them as runtime edges. Without a runtime in place, treat the graph as a point-in-time artifact.
- **No cross-tenant graph leakage.** Postgres row-level security enforces tenant scope on every graph read and write. A graph query authenticated as tenant A will never include nodes or edges that belong to tenant B, even when a shared upstream provider node would otherwise look common across tenants. This is enforced at the database, not at the application layer.
- **No completeness claim for every framework.** Framework tags are drawn from a curated subset, not the full source standard for every framework. See [ARCHITECTURE.md § Coverage per framework](../ARCHITECTURE.md#coverage-per-framework) for the per-framework control counts.
- **No exhaustive centrality.** Bottleneck ranking is *approximate* betweenness: shortest-path traversals from a bounded, deterministic sample of source nodes (50–200, scaled to graph size, drawn by fixed stride over sorted node ids so the answer never depends on insertion order). Every response carries `sampled_sources` and `total_nodes`, and nodes no sampled path crossed are omitted rather than reported at score `0.0`. Treat the ranking as a strong signal, not a proof that no other choke point exists.
- **No complete answer from a bounded load.** When a snapshot is loaded under a node budget, every projection of it — filtered views, the typed inventory / attack-path / lateral-movement / compliance / runtime views, the estate roll-up and its drill-downs — reports `completeness.truncated` with the reason(s) that applied and the pre-truncation estate total (`total_nodes_source` on roll-up summaries, `stats.total_nodes_source` on graph responses). A filter cannot make truncation untrue: the nodes that were never read might have matched.

### Proposed scenarios are not observed evidence

The Investigation Canvas can save a bounded architecture delta against one
exact `base_scan_id` and compare `Current`, `Proposed`, and `Difference` over
the same canonical entity and relationship taxonomy. This is a design tool,
not a second scanner:

- `Current` is the immutable persisted scan snapshot.
- `Proposed` is a server-authored overlay whose additions are labeled
  `evidence_state=proposed`, `observed=false`, and `deployed=false`.
- `Difference` names additions, removals, posture changes, and observed paths
  touched by the proposal. A touched path is not reported as eliminated or
  remediated.

Scenarios are tenant-scoped, revisioned, and pinned. The comparison endpoint
does not fall forward to the latest snapshot when the base is missing or the
selected snapshot differs; it returns an explicit unavailable state. Scenario
operations never write into observed graph tables, findings, SARIF, runtime
enforcement, or materialized attack paths. Only a later scan can verify that a
proposed state was deployed and establish its findings or paths.

---

## 5. Re-baseline procedure

Issue #2259 ships a graph-edge accuracy CI gate that compares each scan's emitted edges against a snapshot fixture. When an intentional graph-shape change ships — a new entity type, a new edge kind, a corrected emission rule — the snapshot fixtures must be regenerated.

```bash
python scripts/rebaseline_graph_edges.py
```

This is the **only** correct way to refresh the snapshot. It is appropriate when:

- A new `EntityType` or `RelationshipType` is added to `src/agent_bom/graph/types.py` and wired through the bridge.
- An emission rule is intentionally changed (for example: `exposes_cred` now emits on additional env-key heuristics, or `shares_server` raises its minimum-agent threshold).
- A scanner upstream of the graph is repaired and starts producing additional nodes or edges that the snapshot must now reflect.

It is **never** appropriate to:

- Silence a regression that surfaced on a normal feature branch.
- "Refresh the baseline" because tests are red and the cause hasn't been investigated.
- Re-baseline on main without a corresponding code change that explains *why* the shape changed.

Every re-baseline must land in the same PR as the code change that motivated it. The PR description must call out which entities or edges shifted and why. Reviewers should reject re-baseline-only PRs — they hide regressions.

---

## 6. Coverage gaps

These are the shapes we do not model yet. They are documented here so operators do not assume coverage that does not exist.

- **Cross-cluster federation.** A multi-cluster Kubernetes fleet appears in the graph as multiple disjoint `cluster` subgraphs. Workloads that federate across clusters (KubeFed, Karmada, Argo CD ApplicationSets) are not stitched together — each cluster's nodes stay in their own component.
- **Cross-cloud trust relationships.** AWS ↔ GCP ↔ Azure cross-account trust (assume-role chains across providers, GCP workload-identity-federation pointing at AWS, Azure-AD federated apps trusting Okta) is not represented as a graph edge. Provider-internal trust (one AWS account → another AWS account) is captured; cross-provider trust is not.
- **Real-time tool-call traces.** `invoked`, `accessed`, and `delegated_to` edges live in the proxy / gateway audit log only. The static graph does not back-fill them from audit logs after the fact. To investigate a runtime path, query the audit log directly; the graph view of runtime traffic is forward-only from the moment proxy / gateway runtime is enabled.
- **Multi-region cloud asset stitching.** Cloud resources discovered in different regions for the same account currently show as separate `cloud_resource` nodes. Region-aware deduplication (one logical resource that spans multiple regions, e.g. a global S3 bucket) is partial.
- **Agent-to-agent runtime collaboration outside MCP.** Agents that talk over non-MCP transports (custom RPC, message queues, direct HTTP between LLM frontends) are invisible to the static graph. They surface only when a runtime in the path emits `delegated_to` edges.
- **Identity provider chains.** SCIM ingest models the customer's primary IdP. Federated chains (Okta → Azure AD → AWS IAM Identity Center) collapse into the entry point's `user` and `group` nodes; the upstream IdP graph is not modelled.

These gaps are tracked as roadmap work. None of them block the guarantees in §2.

## Node kinds, ids and package lineage

- **One id scheme per kind.** Packages are `pkg:<ecosystem>:<name>@<version>`
  (an image-scoped occurrence appends `:image:<digest12>`), organizations
  `org:<provider>:<id>`, configuration findings `misconfig:<source>:<id>` and
  advisories `vuln:<id>`. A retired spelling is kept in the node's
  `identity.aliases` and persisted to `graph_node_aliases`, so it still resolves.
  Snapshot diffs compare an old id that the new snapshot records as a one-to-one
  alias under the new id: unchanged, or changed with `previous_id`, never removed
  plus added. Removed rows keep the old snapshot's ids.
- **Images and workloads.** Both are `container` nodes; `attributes.container_kind`
  is `image` (registry image, SBOM subject) or `workload` (pod, deployment,
  task), set only from a recorded resource type or Kubernetes kind. A workload
  `depends_on` the image it runs and is `hosted_on` the cluster or node its
  inventory records.
- **Package dependencies.** `depends_on` package -> package edges join a
  recorded parent to its child within one inventory, only when the parent names
  exactly one package in that ecosystem. No transitive closure is stored; the
  dependency traversal class walks the chain. `is_direct`, `dependency_depth`
  and `parent_package` are recorded on the package node.
- **Package CVEs.** A package's CVE is `vulnerable_to` (package -> advisory)
  plus `affects` (advisory -> package); the roll-up parents the advisory under
  the package through `vulnerable_to`, not a separate `contains` copy.
- **VM CVEs.** A CVE found on a VM is `vulnerable_to` (cloud resource ->
  advisory); the roll-up parents it under that instance. Its node carries the
  occurrence's `reachability` / `reachability_basis` and, when the finding has
  one, `effective_reach_score` / `effective_reach_band`. A path that starts at
  the finding's own holder is the occurrence itself, so it never makes the
  finding `graph_reachable` and the holder is never listed as a reach source.

## Correlated runtime identity and path proof

Correlation manifests and edge receipts identify the join contract as
`scoped-identity.v7`. Container occurrences join only when an authoritative
runtime identifier and its provider and account, cluster, or host scope match
within the requesting tenant. Kubernetes pod identifiers additionally require
container names. Missing identity stays specific to the source snapshot. Image
digests remain artifact metadata; reusing an image does not join deployment
permissions.

Historical receipts remain stored. Correlated edges without the current identity
version require recomputation before they can support a verified path. Run a new
correlation using the original source snapshots; correlating an already merged
legacy output does not recover the original occurrence boundaries or upgrade
its receipts. Existing snapshots remain available for inspection and rollback.

A verified path requires a complete recorded analysis and one ordered receipt
for every hop, matching the source, target, and relationship. Receipts must be
directed, traversable, fresh, untruncated, backed by source references and recorded
relationship provenance, and use the current correlation identity contract.
Incomplete or historical evidence remains unavailable for verification. API and
MCP exposure projections also check the matching directed topology. Page-size
limits on the path queue do not certify or invalidate an individual hop receipt.

Each hop must identify exactly one directed relationship by source, target and
relationship type. Missing types or conflicting duplicate records remain unknown.
`canonical_edge_id` identifies the recorded source edge in API/MCP receipts and
the expanded UI inspector. Merged runtime observations retain separate event and
trace references; a denial or failed aggregate cannot disappear when another
source reports an attempt. Incomplete or bounded runtime receipt lists prevent
verification. An invocation attempt does not establish successful downstream use.

MITRE mappings describe potential techniques with source-backed prerequisites.
[T1530](https://attack.mitre.org/techniques/T1530/) requires cloud-object storage
context: the path mapper accepts an exact recorded native read permission and
labels it modeled at collection, with current access and collection unproven.
[AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) requires an AI-agent tool
invocation: an exact runtime reference supports an attempt, with adversarial
intent and outcome unproven. Generic vulnerability, credential, role, datastore
or tool-inventory edges do not meet those prerequisites. Mapping confidence stays
unavailable without a calibrated basis. A mapped technique is not evidence that
an attacker used it. Malformed legacy mapping entries are skipped independently;
the stored historical payload is not rewritten.

Scanner ATLAS tags require an advisory CWE, explicit AI/MCP inventory context,
and an exact catalog bridge from that CWE through ATT&CK to an ATLAS reference.
Package names, severity, credentials and declared tool capabilities alone do not
establish an ATLAS technique. These are weakness associations, with
`execution_proven: false`; catalog membership is not detection coverage.

New scans freeze `atlas_mapping_evidence` with the CWE, ATT&CK reference, ATLAS
version and both normalized catalog SHA-256 digests. Finding JSON, SARIF,
CycloneDX properties, SPDX annotations and graph edge receipts preserve that
association. The scan's **Mapping sources** disclosure shows the same source
chain. Historical tags without receipts remain unqualified; reading an old scan
does not silently re-map it against a newer catalog. Graph merges retain whole
conflicting catalog receipts instead of combining their hashes or claims.

Attack-path campaigns expose `priority_score` with
`priority_method: structural_path_rank.v1` for structural prioritization.
`exploitability` and `expected_risk_reduction` remain nullable, each with its own
`*_evidence` status and references. Historical numeric values without supporting
assessment metadata become unavailable; priority is not a substitute for either
quantity. Finding severity is displayed separately from path priority.

Exposure-path projections use the maximum known vulnerability/misconfiguration
severity, independently of asset priority. Missing finding severity remains
unknown, including when a high-priority asset is present. API and MCP legacy
`reachability: confirmed` labels are downgraded to unknown when the current
evidence dimensions cannot support that verdict. Projection qualification does
not rewrite stored path receipts.

Reachability verdict ladder (`agent_bom.core.reachability`): `unlikely` when
graph, symbol or dependency evidence disproves reach; `confirmed` only with
function-level (`function_reachable`) or runtime-observed (`runtime_observed`)
basis; `likely` for a modeled graph path (`graph_path`, including complete
`directed_provenance_backed_hops`), package or dependency reachability;
otherwise `unknown`. A persisted `confirmed` whose basis lacks a confirming
entry is read as `likely`. `graph_reachable` still means any inbound attack
path, and keeps its ranking boost.

Every finding surface reads one derivation,
`agent_bom.core.reachability.finding_reachability`, over the evidence stamped
on the row: the findings list and detail, the `reachability` filter and facet
(`reachable` = `confirmed`/`likely`, `unreachable` = `unlikely`, `unassessed`
= `unknown` or never assessed), MCP `findings_query` / `blast_radius`, and
exports. A finding reached only by paths that are themselves `unknown` stays
`unknown` (`unverified_graph_path`). On attack paths, a `vulnerable_to` hop
whose occurrence was never assessed records `applicability_unassessed`: it
does not block a directed, provenance-backed path from `likely`, and the path's
evidence confidence stays `structural`. A review-only advisory match, an
`unlikely` occurrence or an excluding VEX statement still records
`applicability_unverified` and blocks the hop.

### Inspect recorded authorization

In a selected hop, open **Recorded authority** to inspect an evaluator's action,
principal, resource, observation time and matched binding IDs together. The same
optional `hopEvidence[].authority` object is retained by exposure REST responses,
MCP, the graph-paths JSON command and the Python/TypeScript clients. No permission
is re-evaluated in the browser. Missing legacy principal, resource or observation
time remains `null` and appears as **Not recorded**.

A derived permission can instead supply ordered source-edge IDs, the original
grant principal, source snapshot and grant edge. These are selected shortest
structural witnesses per grant/access type, not an exhaustive path set or an
inferred action scope. They do not establish successful execution.

Snowflake object grants are separate `native_grants` receipts. Each retains its
recorded privilege, account, role, object FQN and object type; a native grant is
not an evaluator `allow` decision. Multiple privileges on one relationship remain
separate records. Unknown legacy scope stays null, and grants do not establish
active session roles, required database/schema usage, masking or row-policy effects.

Projection retains at most 16 action receipts, 16 native grants and 16 witnesses, with at most
seven source relationships per witness. Invalid or oversized records are omitted
with explicit reason codes and `status: partial`; valid neighboring records stay
inspectable. Each action receipt accepts at most 16 binding IDs. Arbitrary policy
bodies, tool output and credential fields are excluded. The UI shows four records
per page in a bounded list and treats all identifiers as inert text.

These are historical records, not proof of current access. Conditions, explicit
denies, expiry and revocation still require a fresh evaluation in the relevant
context. Existing path snapshots are not rewritten: rescan or rebuild the derived
snapshot from source edges to populate the new projection. No database migration
is required. Older readers ignore the optional object; retained snapshots remain
available for rollback.

### Exploit story for a CVE occurrence

`GET /v1/graph/exploit-story?finding_id=<id>` (or `?node=vuln:<id>&package=<package node>`)
answers what a vulnerable package puts at risk and how it could be exploited,
from recorded evidence only. The MCP `finding_detail` tool returns the same
payload under `exploit_story`.

- `how` holds only recorded advisory fields: the CVSS 3.x or 4.0 vector decoded
  into words (attack vector, complexity, requirements, privileges, user
  interaction, scope, impact), CWE ids mapped to an attacker capability
  (`agent_bom.cwe_impact.CWE_ATTACKER_CAPABILITIES`), KEV, EPSS, the
  reachability verdict from `core/reachability`, and the fixed version.
- `at_risk` walks dependency edges in reverse from the package to the servers,
  containers and agents that load or use it, then the shared reach policy
  forward from the loaders (trace order excluded, as for finding
  reachability). Items are grouped as agents, MCP servers, tools, credentials,
  data stores, cloud resources and identities; each carries its hop-by-hop
  path with every hop's evidence tier, and credentials carry names only.
  The walk is bounded (`max_depth`, node budgets, 50 listed items per group)
  and reports `completeness`.
- `narrative` is assembled clause by clause; each clause lists the payload
  fields it reads in `fields`, and a missing field drops its clause. The
  `basis` says whether the hops behind it were observed or modeled. A story
  shows what an attacker could reach, not that exploitation happened.

### Inspect a selected path's evidence

Use `agent-bom graph-paths exposure --api-url "$AGENT_BOM_API_URL" --format json`
with the control plane's provisioned authentication. The response includes a
`hopEvidence` array alongside `evidenceDimensions`. Continue with the returned
cursor to keep the same tenant, snapshot, and risk filter. In the dashboard,
select the path, expand its evidence disclosure, then select one hop to inspect
its receipt. The filter searches the loaded path; it does not run a new traversal.

| Receipt field | Interpretation |
|---|---|
| `source_snapshot_ids` | Recorded source snapshots, displayed as inert identifiers. The inspector does not fetch or execute locators. |
| `freshness`, `relationship_provenance`, `correlation_identity_status` | Independent qualifications; missing or mismatched receipts remain unavailable. |
| `runtime_observed_state` | Whether an invocation or blocked attempt was observed; this is not proof of effective permission. |
| `runtime_outcome` | `blocked`, `failed`, or `unknown`. An allowed invocation and a mixed aggregate leave the downstream outcome unknown. |
| `direction`, `traversable` | Eligibility for graph traversal, separate from successful execution. |

A blocked receipt or an aggregate in which every observed attempt failed cannot
support confirmed downstream reachability. A CVSS network attack vector, KEV
entry, EPSS score, or a bare exploitability label does not supply an
exploitability assessment. An assessment must satisfy the existing evidence
contract, including references; its status and limitations remain visible.

The hop projection excludes unclassified receipt fields. Older snapshots need
no database migration: receipts use the existing JSON storage, and missing
outcomes project as unknown. Projection does not change historical rows. To
refresh an assessment, collect new source evidence and correlate a new snapshot;
a display change or a proposed fix is not remediation verification. Preserve
old snapshots for comparison. A rollback to an evaluator that ignores negative
outcomes can restore overstated labels; do not treat those labels as proof.

Permission overlays exclude context-only access, membership, and delegation
links from newly derived authority. This does not reconstruct missing action or
policy-condition evidence. Previously persisted derived edges remain historical
records; rebuild from source evidence to obtain the corrected derivation.

Exposure pages retrieve relationships between their selected node IDs. Other
incident-edge queries retain their existing behavior. Response limits and cursor
continuation still apply; a small rendered page does not establish full-estate
coverage. The inspector renders at most eight relationship rows at once and
keeps the original hop positions when filtering.

Node IDs containing slashes (filesystem findings and scoped package identifiers)
use `GET /v1/graph/node-context?node_id=...` and
`GET /v1/graph/node-neighbors?node_id=...`. These authenticated query aliases
preserve the complete ID without URL-path decoding ambiguities. Existing
single-segment node routes remain supported.


### Campaign verification and graph remediation

Run `agent-bom campaigns list --format json`, then use the returned campaign ID
and version with `agent-bom campaigns verify CAMPAIGN_ID --version VERSION`.
Both commands use the control plane's configured authentication. Verification
checks original finding identities even if advisory enrichment moved them to
another remediation group, plus current replacement findings in the original
group. `remaining_count` counts distinct matches; it can exceed the baseline
member count when new affected instances appear.

A complete 90-day findings window is not a fresh scan receipt for the original
target scope. With no matching findings, verification returns HTTP 409 with
`outcome: unavailable_evidence` and
`retry_state: awaiting_fresh_scope_evidence`; workflow state remains unchanged.
The MCP workflow preserves these fields and the dashboard displays the reason.
No absence-based `verified_fixed` result is issued, including from older cached
success responses. Existing saved workflow states are not rewritten.

Collect the same target scope again and inspect its new graph snapshot for
remaining and alternate routes. A proposed edge removal changes only a scenario;
it does not revoke provider access, trigger a rescan, or verify remediation.
The campaign endpoint currently does not bind baseline/rescan coverage receipts
or evaluate alternate graph paths, so it cannot certify access revocation from
that comparison. Retain those source receipts and compare the new snapshot's
qualified hop evidence before deciding whether more remediation is needed.

## Snowflake account-local identity

Snowflake users, roles and object names are local to the account recorded by the
source lane. The builder stages object, service, identity and governance lanes
by that exact account before joining their nodes. A lane without an account
stays separate from other lanes; matching names or FQNs do not establish a shared
account. External destination buckets keep their own provider context.

Coherent single-account reports retain existing graph node IDs. Mixed-account
reports use deterministic scoped IDs and retain `legacy_graph_id` plus the
account-local source key (`snowflake_local_id`). Correlation joins these keys
only with the same recorded account inside one tenant. Account aliases and case
variants are not assumed equivalent. Historical access remains distinct from
current authorization and active session identity.

Existing snapshots and their scan/node deep links remain unchanged. Rescan or
rebuild original source reports to populate missing identity scope, then create
a new correlation. Already-collapsed legacy mixed-account graphs cannot recover
separate identities by correlating the merged output again. Legacy object nodes
with exact account and FQN evidence can still join; legacy identities without
account evidence remain specific to their snapshot.

## Relationship observation intervals

A later scan is not necessarily a complete replacement for the tenant: it may
cover another account, another collector, or an incomplete grant inventory.
Graph persistence therefore does not set an earlier edge's `valid_to` or emit
OCSF Close activity merely because that edge is absent from a later snapshot.
Native source-provided interval ends remain intact.

Positive timestamp continuity requires the same edge key, exact collector
source, and matching recorded provider/account namespaces for both endpoints.
Missing, malformed or conflicting scope remains unknown. A previously bounded
interval is not extended into a new observation. These timestamps describe
recorded relationships; they do not establish continuous effective permission.

Replay (`GET /v1/graph/edges/active`) returns observations whose recorded interval
includes the requested time. It deduplicates only exact scoped re-observations;
unknown scope stays specific to its source snapshot. An open interval means no
end was recorded, not that current access is authorized. Old/new snapshot diffs
still describe membership differences and do not establish revocation.

This changes the earlier tenant-wide replacement assumption. Scope-free legacy
snapshots no longer inherit unrelated timestamps or automatically close earlier
observations. Existing stored interval ends are not rewritten; rebuild from
original source evidence when an earlier version inferred an end from absence.
Verified access removal requires fresh, scoped native evidence and evaluation.

### Native cloud resource identity

AWS service resources (RDS, DynamoDB, Lambda, EKS, ELB, VPC, KMS and Secrets
Manager), GCP estate resources (GKE, Cloud Run, Functions, Cloud SQL, VPC, disks
and Pub/Sub), and normalized Azure resources use qualified provider IDs when
available. Local IDs and name-only records include the account/project, location
and resource group in their graph key. Native evidence stays unchanged; Azure
ARM keys compare case-insensitively. Renaming a display label does not replace
a node identified by a qualified native ID.

Benchmark joins use the recorded account scope and preserve native database
nodes. A missing native-ID match or ambiguous name produces an unresolved
resource reference, never a fallback to a foreign same-named asset. Other
inventory paths retain their existing identity contracts.

These keys differ from older name-based snapshots. Rebuild a snapshot from its
source report to adopt them; historical snapshots and their saved node links
retain their original IDs. No implicit cross-cloud identity equivalence is
inferred from matching names.

## Portable investigations

Select an entity in a saved graph, open **Relationships → Export investigation**,
then choose **Download investigation JSON**. The local JSON file contains the
loaded relationship pages, exact scan/entity IDs, snapshot generation, finding
node IDs, any originating finding context, source labels and relationship evidence.
Load more relationships before downloading to include a wider neighborhood.

Use `return_url` to reopen the selected entity on the original control plane.
Access and snapshot retention are still required. The bundle preserves the
generation at export time; a later replacement under the same scan ID can change
what the link shows. Compare the recorded generation before treating a reopened
view as the same evidence.

This is an unsigned browser export of existing authenticated API results, not an
independent attestation or a full-snapshot export. It includes entity names and
source metadata. Page completeness and missing endpoints are retained; collection
coverage stays unknown. Recorded edges do not prove execution, exploitation or
successful access. Unavailable, stale or currently loading relationship reads
cannot be exported. No write to the control plane or automatic upload occurs.

## Saved snapshot updates

Saved graph views remain pinned while new scans finish. While a graph view is
visible, the dashboard checks up to 40 recent saved snapshot records every 30
seconds, with a manual **Check for updates** action. This interval is a polling
policy, not an end-to-end latency guarantee. Running scan progress is separate.

When a newer snapshot of the same kind is available, choose **Open newer
snapshot** or **Keep current**. Switching reloads the selected view and retains
its URL filters and entity/finding context. A missing entity in the new snapshot
remains missing; it must not be replaced with an unrelated entity. New snapshots
can cover a different source scope; inspect their evidence before comparing them.

Background checks do not replace graph data, selection or viewport. Hidden tabs
do not poll. Session changes discard pending results; denied access stops
background retries until the session changes or a manual retry. Failed checks or
a selected snapshot outside the bounded list mean freshness is unknown. Correlated
and scan snapshots are not mixed, and scenario views do not offer this switch.

## Attack-path queue coverage

Investigation filters apply to loaded queue pages and enriched priority cards.
An empty filtered page does not establish that the snapshot has no matching
path. **Load next 25 paths** fetches one more bounded page while retaining the
filters. Loaded matches and unexamined pages are reported separately; the UI
does not invent a total matching count for evidence it has not loaded. Completing
the available pages does not override a bounded server ranking window or partial
source analysis. Page failures retain the loaded investigation and permit retry.

Additional pages must match the tenant, resolved scan ID and committed read
revision, and advance to the requested next offset. Navigation cancels outstanding
continuation requests; a changed authenticated session remounts the investigation.
The backend rejects replaced revisions. Revision tokens are consistency controls,
not cryptographic attestations or a replacement for authorization.

Severity filters use server-authored finding severity, or the highest recorded
finding-node severity for older responses. A path priority score, an asset risk
score or missing severity never supplies a critical finding classification.

The ranked path response retains edges between consecutive hops in their stored
direction. A bidirectional edge remains available when a path traverses it in
reverse; a reversed directed edge and unrelated chords are excluded. Retaining a
relationship witness does not turn inventory into observed execution, effective
permission or confirmed exploitation.

### Graph interchange compatibility

Authenticated clients can discover the graph taxonomy and compatibility policy
with `GET /v1/graph/schema`. Serialized `UnifiedGraph` documents use
`schema_version: agent-bom.graph/v1`. The Python reader accepts older unversioned
documents and ignores unknown optional fields. An explicit unsupported version
or unknown entity/relationship kind is rejected: consumers must not silently
remove unknown topology and then report a complete analysis. A version identifies
the interchange shape, not provider qualification or a standalone SDK release.

Preserve `id`, `canonical_id`, tenant, snapshot, relationship direction and
source timestamps when integrating. A canonical identifier is a join key within
an authorized scope; it does not authorize a cross-tenant join. Node
`evidence_provenance` and exposure-reference `evidenceProvenance` share
`agent-bom.graph-evidence/v1`. Sources and source snapshots describe collection;
a collector name never upgrades a node to successful execution. Timestamps are
recorded observation times, not a fresh authorization check. Modeled, static and
runtime evidence remain distinct, and a possible path is not proof of compromise.

Scan graph exports (`GET /v1/scan/{job_id}/graph-export`, `agent-bom graph`,
`agent-bom scan -f graph`) name nodes with the same `id` and `entity_type` the
graph API serves for that scan. Their `kind` / `type` field is a display kind
(`pkg_vuln`, `server_cred`, `cve`, ...) for styling only; join on `id`. Package
and advisory nodes keep their pre-0.111 spelling in `attributes.legacy_id`.

First retrieve the schema, then fetch a pinned graph or exposure path and save its
scope and completeness alongside the evidence. Use snapshot diffs to investigate
changes; confirm effective permission and successful access against their own
receipts before taking an enforcement action.

### Generation-pinned continuation

`GET /v1/graph`, `/graph/search`, `/graph/agents`, `/graph/attack-paths` and
`/graph/rollup` return `snapshot_generation` on revision-capable stores. Send
that token and the resolved scan ID with every later `offset` request. Rollup
continuation applies to a container’s child pages. A `cursor` from `GET /v1/graph`
or `/graph/attack-paths` carries its generation, so `snapshot_generation` is
optional with it; a supplied token that differs from the cursor's returns 409,
and a cursor never combines with `offset` (400) on `/v1/graph`, `/graph/search`,
`/graph/agents`, the attack-path queues or `/v1/inventory/assets`. A cursor that
does not decode returns 422 on every route. Missing tokens on an `offset`
continuation return 422; a replaced snapshot returns 409 and requires restarting
at the first page. A replacement during hydration discards the entire response.
The UI retains already loaded evidence and exposes the failure without appending
mixed rows. Unsupported backends reject pinned continuation with 501; legacy
unpaged overview/search/rollup reads remain available without a revision.
Attack-path pages require revision support even on their first request.

A read revision changes on every committed snapshot write, even when a retry
reuses its rollback ownership token. Ownership is retained separately. Incident
edge cursors and API/MCP exposure continuations also bind to the read revision.
PostgreSQL deployments must apply migration `20260930_01` before starting these
readers. Drain older writers during rollout: they do not populate the new read
revision. Keep the additive column when rolling back application code; restart
investigations after any rollback rather than continuing old cursors.


### SQLite initialization and contention

Cold schema initialization and failed-probe invalidation use the same bounded,
per-file writer admission as graph mutations. A blocked database cannot hold an
initialization lock for unrelated files. Concurrent first reads of the same file
still initialize once; initialized WAL readers stay outside writer admission.
File replacement is rechecked after admission, and failed initialization is not
cached as healthy. Admission timeout fails the operation with SQLite busy
semantics; it does not return an empty or partially initialized graph.

This coordinates threads in one process. SQLite still arbitrates separate
processes; it does not promise cross-process fairness or production latency.

### Bounded storage qualification

Use a separate, disposable database with migrated schema and a restricted app
role. Configure the PostgreSQL URL and password file through the normal storage
settings; the command does not need migration credentials. For SQLite, supply
an explicit task-owned path. Qualification tenants are retained for inspection.

```bash
python scripts/qualify_graph_store.py --sqlite /tmp/graph-qualification.db --seconds 60 --nodes 1000 --output /tmp/graph-qualification.json
# With AGENT_BOM_POSTGRES_URL and its password file configured:
python scripts/qualify_graph_store.py --seconds 60 --nodes 1000 --output /tmp/postgres-graph-qualification.json
```

The artifact records concurrent writes, paired incident-edge reads, rejected
stale continuations and the final committed revisions for two isolated tenants.
After restarting the test database, run the same backend selection with
`--verify-checkpoint /tmp/postgres-graph-qualification.json --output /tmp/graph-restart.json`
to verify persisted counts and revisions. This bounded synthetic workload is
an operator check, not a sustained production capacity or failover guarantee.

### Revision-consistent blast-radius investigations

Start with `GET /v1/graph/impact?node=<canonical-id>&max_depth=4`. Save its
resolved `scan_id`, `tenant_id`, `snapshot_generation`, `interpretation` and
`completeness` with the result. Pass the resolved scan and revision to
`POST /v1/graph/query` and `GET /v1/graph/node-context` (or `/graph/node/{id}`).
The query accepts the token in its JSON body; detail and impact accept it as a
query parameter. Replacement before or during a read returns 409; discard the
attempt and restart. A backend without revision support returns no revision on
an unpinned read and rejects a requested pin with 501. Do not join those unpinned
results into one investigation.

Impact follows recorded relationships in reverse, including context relationships
that are not marked traversable. To inspect the same semantics, use
`direction: "reverse"` and `traversable_only: false`. These are related nodes,
not confirmed compromised assets or effective permissions. The interpretation
reports execution as not established and collection coverage as unknown. A
truncated or unknown completeness result is a lower bound. The dashboard starts
with a four-node canvas and displays its visible count separately from the
larger impact scope; a small map does not imply a small blast radius.

### Independent process and consumer qualification

Use `--executor processes` on the storage qualification command to create four
spawned workers, each with its own connections: one writer and one reader for
each of two tenants. The workload starts after all workers are ready. Receipts
include process IDs, operation counts, rejected stale continuations and maximum
operation latency. A failed worker fails the command; its error class is retained
without raw database exception text. Existing receipt files are never overwritten.

New checkpoints also contain a deterministic graph-content digest. Repeat
`--verify-checkpoint` after a database restart to detect content changes even when
row counts match. This local digest is an integrity comparison, not a signed or
independently collected audit record. Older count/revision-only checkpoints remain
readable and provide only their original checks.

A separate consumer probes the public HTTP contract without importing server
graph models. Create a viewer API key, keep it in a private file, and run:

```bash
python scripts/qualify_graph_consumer.py --url https://control-plane.example \
  --token-file /secure/viewer-key --scan-id <snapshot-id> \
  --page-size 100 --max-pages 2 --output /secure/graph-consumer-receipt.json
```

Replace `<snapshot-id>` with a saved scan ID. The command uses verified HTTPS
(HTTP is accepted only on loopback), follows no redirects, and writes a new
mode-0600 receipt containing the authorized response pages and their hashes.
Protect this artifact as inventory evidence. It verifies supported contract
versions, stable identities, provenance, relationship direction and one pinned
tenant/snapshot revision. On 409, discard the attempted read and restart; the
consumer never joins changed revisions. Unknown kinds or versions fail closed.

For unfiltered `GET /v1/graph` node pages, `limit` bounds the ranked slice:
the first `completeness.ranked` nodes. Context follows that slice, and every
context node carries `context: true`; ranked nodes have no `context` field.
Context is the agent stack and the containment ancestors
(`completeness.context_nodes`), then the off-page endpoints of returned edges
(`completeness.endpoint_nodes`). The three counts sum to `completeness.returned`
and the length of `nodes`.

Stack and containment context is capped at `completeness.context_limit`
(`max(limit, 500)`). The stack comes first, then ancestors from the top of
the spine down, so the few orgs and accounts outrank the many direct parents.
`completeness.context_omitted` and `context_truncated` report the cut. A cut
node that is the endpoint of a returned relationship returns as an endpoint,
together with its containment relationships. Otherwise its context
relationships are dropped.
Endpoints are bounded by the returned relationships, so a page carries at
most `limit + context_limit` nodes plus one endpoint per returned relationship.
The floor of 500 keeps the containment spine of small canvas pages whole.

Across a cursor walk, every node is ranked on exactly one page, but a context
node can repeat on several pages. This is deliberate: each page stays drawable
on its own. Count ranked nodes for coverage and dedupe context by `id`. The
consumer counts identical copies once, ignoring the `context` marker, and keeps
each original page in the receipt. These conditions fail closed: changed node
evidence, duplicate nodes within a page, repeated ranked nodes, unmarked or
misplaced context, context over its declared bound, inconsistent counts and
oversized ranked slices.

A ranked node page includes at most 1,000 incident relationships, plus its
containment context. `completeness.edge_returned` counts the incident slice;
`edge_limit` states its bound and `edges_truncated` reports omitted relationships.
The overall completeness remains truncated even when every node fits on one
page. Snapshot totals still describe the stored estate, not the displayed slice.
Containment parents are fetched independently through incoming containment
relationships, so a high-degree parent does not require loading its siblings.

For a complete recorded neighborhood, request `GET /v1/graph/incident-edges`
with the selected `node_id`, returned `scan_id` and `snapshot_generation`, then
follow `next_cursor` until it is empty. This endpoint is also returned in
`completeness.edge_expansion_endpoint`. Preserve the revision across requests;
on replacement, restart the investigation. Exhausted node pagination alone does
not prove that every relationship was returned.

Exhausting this bounded set of node pages does not establish source collection
coverage, effective permission or successful execution. Use the retained scope
and completeness when building an integration, then qualify its workload against
the intended database and deployment profile.

SQLite startup repairs for missing relationship time/source metadata use partial indexes; normalized edges do not require repeated full-table scans. The read initialization cache tracks the database file identity, so an offline replacement at the same path receives schema initialization. Replace SQLite files only with all database connections stopped; this is not live restore or failover support. The additive indexes may remain after rollback.

Storage qualification uses the same content, tenant, revision and non-overlapping-page checks in thread and process modes. Private failure receipts retain the worker stage, completed-operation counters, elapsed time and allowlisted SQLite error codes/names, without raw exception messages, SQL or connection strings. A failed worker stops the run; contention errors are failures, not successful reads or silently retried operations. Successful bounded runs do not explain a historical failure whose receipt lacks diagnostic detail.

SQLite graph mutations use bounded FIFO admission per resolved database path within each process, including schema setup and search projection updates. Initialized WAL readers and unrelated database files do not enter this queue. Admission waits at most ten seconds; timeout raises `SQLITE_BUSY` before opening a connection or consuming a streaming producer. SQLite still coordinates separate processes with its existing ten-second lock timeout; local admission does not guarantee cross-process fairness or a total ten-second operation deadline. Failed producers roll back without replay. Removing admission on rollback restores SQLite-only scheduling; no schema change is required.

### Correlation identity scope

New correlations record `scoped-identity.v7`. Assets that carry a strong
provider-native key (qualified ARN, AWS instance id bound to account and region,
Azure ARM id, GCP self link, Kubernetes uid, image digest, principal id,
Snowflake account-qualified name; see `graph/asset_identity.py`) join on that
key exactly as a single build's asset canonicalization merges them, and take the
same canonical id. Otherwise exact provider identities include
recorded provider, account and location scope; runtime IDs also include the
recorded host and environment. Provider/environment dimensions and attributes
are equivalent when they agree. Conflicting values remain separate identities.
Identifier namespaces remain distinct: equal text in a Kubernetes UID, provider
resource ID or directory client ID is insufficient to join nodes. Explicit
aliases such as `arn`/`resource_arn` and `canonical_id`/`stable_id` still join.
Fully qualified regional ARNs and global S3 ARNs keep their identity when only
redundant collection location metadata differs in presence. A recorded region
that contradicts an ARN stays separate; incomplete ARN forms retain local scope.
No missing provider, location or identity is inferred from labels.

Repository entities additionally require an absolute HTTP(S), SSH or Git repository
URL with a host and repository path, plus the commit and file path. `repository`, `repository_url` and `repo_url` are accepted when their
non-empty string values agree exactly after trimming. Forks with the same commit
and path remain separate. Missing or contradictory repository values keep each
observation snapshot-scoped. Local checkout roots and display labels do not
establish repository identity; URL aliases are not guessed. This deliberately
prefers separate evidence over an unproven join.

Existing correlation receipts remain available without rewriting their source
evidence. Earlier identity versions require recomputation from original source
snapshots before path evidence can be considered current. Re-correlating an old
correlated output preserves its legacy identity status on nodes and edges; it
cannot recover scope lost by the original join. To qualify an investigation,
submit the original snapshots to `/v1/graph/correlations`, wait for completion,
and open the new output snapshot and its source receipts. Incompletely located
observations may remain separate; this is preferable to fabricating connectivity.

### Scanner inventory and cross-agent paths

`agent-bom scan --blast-radius-depth 5` keeps the same direct scanner scope as
the default scan. The option remains accepted for command compatibility. Two
agents configuring the same server name, launch recipe, or remote endpoint do
not establish delegation or access to each other's credentials. No hop-based
risk score is synthesized from that overlap.

Use the graph investigation's typed relationships and hop receipts to examine
recorded cross-agent paths. A modeled path, runtime attempt, blocked operation,
and successful execution remain distinct. Legacy transitive fields in stored
reports are retained as supplied historical data; this compatibility option
does not validate or rewrite them.

### Local launch occurrences in inventory exports

The local Agent BOM manifest and JSON inventory snapshot use scoped server
occurrence IDs for their references. Matching executable arguments in different
agent configurations do not establish a shared process. JSON tool, resource and
prompt occurrence IDs retain their parent server scope. Their `canonical_id`
metadata describes the underlying definition and must not replace the scoped
`id` when joining inventory relationships. CycloneDX derives each MCP component
reference from that same scoped server identity; identical remote endpoints can
still share one component while retaining every declaring agent dependency.

A validated UUIDv5 component reference imported from an SBOM is retained on re-export,
including through the manifest and JSON inventory. This is declared document
identity; it does not authorize execution or establish a runtime observation.
Invalid or executable-source declarations cannot override local instance scope.


### Cloud owner scope and network evidence

Cloud asset identity requires mutually consistent owner evidence. Local resource
IDs need a recorded account, subscription or project to correlate across scans.
Qualified native IDs may supply that scope; organization, tenant and globally
qualified resources retain their own scope rather than acquiring the collector's
account. Native-owner disagreements and conflicting scope fields retain the
observation with `identity_scope.status = conflict`. Such observations do not
supply canonical merge keys or traversable hops. Cross-account references in
trust policies and backend bindings are separate relationship evidence, not
alternative ownership claims.

Inventory hierarchy, configured access, protection associations and runtime
calls have distinct relationship and evidence classes. A recorded WAF association
is non-traversable governance evidence, not a vulnerability mitigation. Public
addresses, permissive rules, subnet placement and frontend/backend attachments
alone do not establish effective network reachability. Those bindings remain
visible with unknown reachability until route, rule and endpoint evidence supports
a stronger claim. Missing links do not prove isolation.
