/** Compile-time API examples checked by `npm run typecheck`. */
import type { components } from "../lib/api-schema.generated";

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
