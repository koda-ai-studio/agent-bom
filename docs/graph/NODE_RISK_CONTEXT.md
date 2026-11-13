# Node risk context

Every asset in the graph can carry `attributes.risk_context`: whether it is
reachable from the internet, how privileged it is, how sensitive its data is,
and whether it is a crown jewel. An attack path then reads the way a leader
asks the question: exposure, then the assets in between, then the crown jewel.

The context is derived once per graph build, after every overlay that records
exposure, permissions and classification, by
`agent_bom.graph.risk_context_overlay.apply_node_risk_context`. The rules are
pure functions in `agent_bom.graph.risk_context`. The full rule table is
generated from the code in the [data model](DATA_MODEL.md#node-risk-context).

## Shape

```json
{
  "version": 1,
  "scan_id": "scan-…",
  "sources": ["cloud-inventory"],
  "internet_exposed": true,
  "privilege_level": null,
  "is_admin": null,
  "data_sensitivity": "phi",
  "crown_jewel": true,
  "reasons": [
    {"field": "internet_exposed", "rule": "recorded_internet_exposed", "attribute": "internet_exposed", "value": true,
     "evidence": {"source": "cloud-inventory", "inputs": {"publicly_accessible": true}}},
    {"field": "data_sensitivity", "rule": "recorded_data_sensitivity", "attribute": "data_sensitivity", "value": "phi"},
    {"field": "crown_jewel", "rule": "sensitive_data_store", "attribute": "data_sensitivity", "value": "phi"}
  ]
}
```

A node gets a context only when at least one field is established. Findings,
packages, code and configuration nodes never get one. Each reason names the
attribute that established it and, where the overlay kept one, the receipt
(finding ids of the network rule, the provider flags, the role binding).

## Rules

**Internet exposure** is `true` when any recorded fact shows public
reachability: `internet_exposed`, a provider public flag (`publicly_accessible`,
`is_public`, `public_access`, `public`, `internet_facing`, `endpoint_public`),
or a globally routable `public_ip`. It is `false` only when the same facts are
recorded false and none is true. Otherwise it is `null` (unknown). A positive
fact wins over a negative one. A name such as `public-web` sets nothing.

**Privilege** comes from the effective-permissions verdict
(`admin_equivalence_status`, `admin_equivalent`), a recorded `is_admin`, the
collector's highest policy level (`privilege_level`: admin, write, read), or a
binding to the built-in Kubernetes `ClusterRole/cluster-admin`. A principal
that can only assume an admin role gets `privilege_level:
escalates_to_admin` and keeps `is_admin` unset: a path to admin, not standing
admin. `is_admin` is `false` only when policy analysis returned `not_admin`.

**Data sensitivity** is the classifier's label (`data_sensitivity`), a
classification tier, regulatory frameworks, or a content-sampling result.
`none` records that a classifier found nothing. The CNAPP classifier also
writes `data_sensitivity_basis`: `name` when only the asset name matched a
sensitive keyword, `metadata` when tags, descriptions or classification
fields did. A name-only match is shown as such in the reasons.

**Crown jewel** is `true` when one of these matches, and the reasons list
every rule that matched:

1. `sensitive_data_store`: a `data_store` node with established sensitivity.
   This is the same target the attack-path fusion walks toward.
2. `declared_critical_asset`: an operator-recorded `asset_criticality` or
   `criticality` of `critical`, `crown_jewel`, `tier0` or `tier-0`.
3. `production_secret_store`: a secrets store `resource_type` (`key_vault`,
   `secrets_manager`, `secretsmanager`, `secret_manager`) whose recorded
   `environment` is production.

"Reachable by a privileged identity" is deliberately not a rule: an admin can
reach every resource in its account, so it would mark the whole estate.

## Paths

A path's `ranking_factors.internet_exposed` is true when any hop's exposure
verdict is true: an exposed MCP server or cluster in the middle of a chain is
an attacker entry point too. `ranking_factors.exposed_hop_ids` lists those
hops in path order, and the reasons say where exposure enters and on which
recorded fact, for example `Internet-exposed at claims-api (…), hop 2 of 4:
recorded publicly_accessible.` The verdict is still only a tie-breaker after
evidence tier, KEV, severity, confidence, composite risk and credentials.

## Where it appears

- `GET /v1/graph`, `/v1/graph/node/{id}` and every other node read: in the
  node's `attributes`. The canvas view keeps it.
- Exposure paths over the API and the `exposure_paths` MCP tool: each hop
  reference carries a compact `risk` block with the positive verdicts only
  (`internetExposed`, `crownJewel`, `dataSensitivity`, `admin` or an
  escalation `privilege`). The MCP summary view keeps it on the source and
  target and adds `exposedHops` positions; the full view's `nodes` carry the
  whole context with its reasons, as the node read does.
- Graph exports in JSON and GraphML (`attributes_json`) carry the attribute.
  The SBOM and SARIF formats do not map graph nodes and are unchanged.
- The attack-path graph draws the internet, privileged, sensitive-data and
  crown-jewel markers from it, and the node panel lists each reason with its
  scan and sources.

Snapshots saved before this field existed have no context; readers fall back
to the flat attributes they recorded.
