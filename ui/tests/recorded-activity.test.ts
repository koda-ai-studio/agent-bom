import { describe, expect, it } from "vitest";
import { GRAPH_EDGE_KIND_META } from "@/lib/graph-schema.generated";
import { relationshipLegendItem } from "@/lib/graph-utils";
import { RELATIONSHIP_SCOPE_MAP } from "@/lib/graph-page-data";
import { RelationshipType } from "@/lib/graph-schema";

describe("persisted runtime observations", () => {
  it("remain non-traversable recorded metadata in the runtime view", () => {
    expect(GRAPH_EDGE_KIND_META.recorded_activity.traversable).toBe(false);
    expect(RELATIONSHIP_SCOPE_MAP.runtime).toContain(RelationshipType.RECORDED_ACTIVITY);
    const legend = relationshipLegendItem("recorded_activity");
    expect(legend.label).toContain("execution unconfirmed");
    expect(legend.description).toContain("permissions are unconfirmed");
    expect(legend.dashed).toBe(true);
  });
});
