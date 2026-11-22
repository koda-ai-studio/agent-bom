import { expect, it } from "vitest";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import type { UnifiedGraphData } from "@/lib/graph-schema";

it("drops a shared-server correlation when both agents' use of that server is drawn on the card", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const path = [...graph.attack_paths].sort((a, b) => b.composite_risk - a.composite_risk)[0]!;
  const model = buildAttackPathGraphModel(graph, path, {});
  const relationships = model.edges.map(edge => `${edge.source}-${edge.relationship}->${edge.target}`);
  expect(relationships).toContain("agent:developer-copilot-uses->server:filesystem");
  expect(relationships).toContain("agent:sre-runbook-uses->server:filesystem");
  expect(relationships.some(edge => edge.includes("shares_server"))).toBe(false);
});
