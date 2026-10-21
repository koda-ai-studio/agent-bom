/** Compile-time API examples checked by `npm run typecheck`. */
import type { components } from "../lib/api-schema.generated";

import type { AttackPath, UnifiedEdge, UnifiedNode } from "../lib/graph-schema";
import type { NodeRiskAssessment } from "../lib/node-risk-assessment";

type Schemas = components["schemas"];

// The node serializer omits dimensions with no recorded value.
export const sparseDimensions: Schemas["GraphNodeDimensions"] = {};

// Rollups return summaries, without the full path's evidence fields.
export const rollupPath: Schemas["GraphAttackPathSummary"] = {
  source: "agent:example",
  target: "package:example",
  hops: ["agent:example", "package:example"],
  composite_risk: 0,
  summary: "Recorded dependency",
};

// Historical snapshots remain usable without newer provenance and risk fields.
export const legacyNode: UnifiedNode = {
  id: "agent:example", entity_type: "agent", label: "Example agent",
  category_uid: 1, class_uid: 1, type_uid: 1,
  status: "active", risk_score: 0, severity: "none", severity_id: 0,
  first_seen: "", last_seen: "", attributes: {},
  compliance_tags: [], data_sources: [], dimensions: {},
};
export const legacyEdge: UnifiedEdge = {
  id: "edge:example", source: "agent:example", target: "package:example",
  relationship: "depends_on", direction: "directed", weight: 1, traversable: true,
  first_seen: "", last_seen: "", evidence: {}, activity_id: 0,
};
export const legacyPath: AttackPath = {
  ...rollupPath, edges: [legacyEdge.id],
  credential_exposure: [], tool_exposure: [], vuln_ids: [],
};

// Generated open-record index signatures must not bypass UI field validation.
export const invalidRisk: UnifiedNode = {
  ...legacyNode,
  // @ts-expect-error Numeric risk must not accept a wire string.
  risk_score: "0",
};
export const misspelledNode: UnifiedNode = {
  ...legacyNode,
  // @ts-expect-error Unknown top-level fields are not UI extension points.
  risk_socre: 0,
};
export const invalidDirection: UnifiedEdge = {
  ...legacyEdge,
  // @ts-expect-error The UI only supports these two edge directions.
  direction: "sideways",
};
export const invalidAssessment: NodeRiskAssessment = {
  // @ts-expect-error A score does not imply a valid assessment status.
  status: "clean", basis: null, scope: null,
};
