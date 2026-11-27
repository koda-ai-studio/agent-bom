import { expect, it } from "vitest";
import { recordedBoundaries, scopeBreadcrumb } from "@/lib/graph-recorded-boundaries";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import type { UnifiedGraphData } from "@/lib/graph-schema";
const visible = (ids: string[]) => ids.map((id, i) => ({id, x: i * 220, y: 200, width: 152, height: 136}));
it("collapses equivalent scope ancestry and derives packages and local capabilities without mutating evidence", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const original = JSON.stringify(graph);
  const frames = recordedBoundaries(graph, visible(["display:internet", "container:copilot-portal", "agent:developer-copilot", "pkg:next", "server:filesystem", "tool:exec", "cred:aws", "server:github"]));
  expect(frames).toHaveLength(1);
  expect(frames[0]!.label).toBe("AWS prod account › prod-ai-control-plane › eks-ai-runtime");
  expect(frames[0]!.members).toEqual(["container:copilot-portal", "agent:developer-copilot", "pkg:next", "server:filesystem", "tool:exec", "cred:aws"]);
  expect(frames[0]!.contextMembers).toEqual(["server:filesystem", "tool:exec", "cred:aws"]);
  expect(JSON.stringify(graph)).toBe(original);
});
it("does not infer hosting from use without stdio or from access", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  graph.nodes.find(node => node.id === "server:filesystem")!.attributes.transport = "sse";
  expect(recordedBoundaries(graph, visible(["server:filesystem", "tool:exec", "cred:aws", "role:prod-admin"]))).toEqual([]);
});
it("does not assign a shared package exclusively to one scope", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  graph.edges.push({...graph.edges.find(edge => edge.target === "pkg:next")!, id: "shared-package", source: "server:github"});
  const frames = recordedBoundaries(graph, visible(["container:copilot-portal", "pkg:next"]));
  expect(frames[0]!.contextMembers).toContain("pkg:next");
});

it("names the outermost recorded scope as one breadcrumb and none for unscoped entities", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  expect(scopeBreadcrumb(graph, ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:github"])).toBe("AWS prod account › prod-ai-control-plane › eks-ai-runtime");
  expect(scopeBreadcrumb(graph, ["display:internet", "server:github"])).toBeNull();
});
