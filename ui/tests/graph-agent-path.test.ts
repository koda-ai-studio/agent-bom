import { expect, it } from "vitest";
import { agentPathGraph } from "@/lib/graph-agent-path";
import { scopeEvidenceGraph } from "@/lib/graph-scope-evidence";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import counts from "./fixtures/product-proof-rollup.json";

function sample() {
  const graph = scopeEvidenceGraph(buildGraph() as unknown as UnifiedGraphData, "agent:developer-copilot");
  const flow = buildUnifiedFlowGraph(graph, { layers: createExpandedGraphFilters().layers, severity: null, agentName: null, vulnOnly: false, maxDepth: 32 });
  flow.nodes = flow.nodes.map(node => ({ ...node, data: { ...node.data, findingAggregate: counts.node_aggregates[node.id as keyof typeof counts.node_aggregates]?.aggregate, onExploreFindings: () => {} } }));
  return { graph, flow };
}

it("lays out the exposure spine and incoming identity chain in hop order, retaining original evidence", () => {
  const { graph, flow } = sample();
  const original = JSON.stringify(graph);
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  const x = (id: string) => result.nodes.find(node => node.id === id)!.position.x;
  const path = ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:filesystem", "display:scope-findings:server:filesystem"];
  for (let i = 1; i < path.length; i++) expect(x(path[i]!)).toBeGreaterThan(x(path[i - 1]!));
  expect(x("sa:jit-review")).toBeLessThan(x("role:prod-admin"));
  expect(x("role:prod-admin")).toBeLessThan(x("agent:developer-copilot"));
  expect(result.nodes.some(node => node.id === "agent:sre-runbook")).toBe(false);
  expect(result.nodes.find(node => node.id === "server:filesystem")!.data.scopePeers?.[0]?.label).toBe("SRE Runbook Agent");
  const hosting = result.edges.find(edge => edge.data?.relationship === "hosted_on")!;
  expect(hosting).toMatchObject({ source: "container:copilot-portal", target: "agent:developer-copilot", data: { originalSource: "agent:developer-copilot", originalTarget: "container:copilot-portal", relationshipLabel: "Hosts" } });
  expect(result.edges.filter(edge => !edge.data?.displayOnly).every(edge => graph.edges.some(record => record.id === edge.id))).toBe(true);
  const privilege = result.edges.find(edge => edge.data?.relationship === "can_access")!;
  expect(privilege.style?.strokeDasharray).toBeTruthy();
  expect(privilege.style?.stroke).toBe("var(--graph-edge-risk)");
  for (const edge of result.edges.filter(edge => ["uses", "hosted_on"].includes(String(edge.data?.relationship)))) expect(edge.style?.strokeDasharray).toBeUndefined();
  const pathPairs = new Set(path.slice(1).map((id, index) => `${path[index]}>${id}`));
  for (const edge of result.edges) expect(edge.style?.stroke === "var(--graph-edge-exposure)").toBe(pathPairs.has(`${edge.source}>${edge.target}`));
  expect(JSON.stringify(graph)).toBe(original);
});

it("keeps recorded evidence solid, unknown findings absent, and unexposed graphs without Internet", () => {
  const { graph, flow } = sample();
  graph.nodes.forEach(node => { node.attributes.internet_exposed = false; });
  flow.nodes.forEach(node => { node.data.attributes = { ...node.data.attributes, internet_exposed: false }; node.data.findingAggregate = undefined; });
  graph.edges.forEach(edge => { edge.evidence = { tier: "static_scan" }; });
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  expect(result.nodes.some(node => node.id === "display:internet" || node.type === "findingGroupNode")).toBe(false);
  expect(result.edges.filter(edge => !edge.data?.displayOnly).every(edge => !edge.style?.strokeDasharray)).toBe(true);
  expect(result.edges.some(edge => edge.data?.exposurePath)).toBe(false);
});
