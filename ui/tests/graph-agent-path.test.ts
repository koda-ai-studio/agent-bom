import { expect, it } from "vitest";
import { agentPathGraph } from "@/lib/graph-agent-path";
import { scopeEvidenceGraph } from "@/lib/graph-scope-evidence";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import counts from "./fixtures/product-proof-rollup.json";

function sample() {
  const graph = scopeEvidenceGraph(buildGraph() as unknown as UnifiedGraphData, "agent:developer-copilot", true);
  const flow = buildUnifiedFlowGraph(graph, { layers: createExpandedGraphFilters().layers, severity: null, agentName: null, vulnOnly: false, maxDepth: 32 });
  flow.nodes = flow.nodes.map(node => ({ ...node, data: { ...node.data, findingAggregate: counts.node_aggregates[node.id as keyof typeof counts.node_aggregates]?.aggregate, onExploreFindings: () => {} } }));
  return { graph, flow };
}

it("ends one exposure story at the crown-jewel data an exposed credential opens, with findings above each owner", () => {
  const { graph, flow } = sample();
  const original = JSON.stringify(graph);
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  const pos = (id: string) => result.nodes.find(node => node.id === id)!.position;
  const path = ["display:internet", "container:copilot-portal", "agent:developer-copilot", "server:filesystem", "cred:aws", "store:ai-training"];
  for (let i = 1; i < path.length; i++) expect(pos(path[i]!).x).toBeGreaterThan(pos(path[i - 1]!).x);
  for (const id of path.slice(1)) expect(pos(id).y).toBe(pos("display:internet").y);
  expect(pos("tool:exec").x).toBe(pos("cred:aws").x);
  expect(pos("tool:exec").y).toBeGreaterThan(pos("cred:aws").y);
  expect(pos("server:github").y).toBe(pos("tool:exec").y);
  // The crown rests on the data store's recorded sensitivity, not on the credential.
  expect(result.nodes.find(node => node.id === "store:ai-training")!.data.attributes?.risk_context).toMatchObject({ crown_jewel: true });
  expect(result.nodes.find(node => node.id === "cred:aws")!.data.attributes?.risk_context).toBeUndefined();
  for (const edge of result.edges) expect(Math.abs(pos(edge.target).x - pos(edge.source).x)).toBeLessThanOrEqual(248);
  for (const owner of ["agent:developer-copilot", "server:filesystem"]) {
    const group = result.nodes.find(node => node.id === `display:scope-findings:${owner}`)!;
    expect(group.data.readingFindings?.count).toBe(1);
    expect(group.position.y).toBeLessThan(pos(owner).y);
    expect(group.position.x - pos(owner).x).toBeLessThanOrEqual((pos("server:filesystem").x - pos("agent:developer-copilot").x) / 2);
    expect(result.edges.find(edge => edge.target === group.id)).toMatchObject({source: owner, data: {exposurePath: false, traversable: false}});
  }
  for (const excluded of ["sa:jit-review", "role:prod-admin", "agent:sre-runbook"]) expect(result.nodes.some(node => node.id === excluded)).toBe(false);
  expect(result.nodes.find(node => node.id === "agent:developer-copilot")!.data.scopeAdmin?.label).toBe("prod-ai-admin");
  expect(result.nodes.find(node => node.id === "server:filesystem")!.data.scopePeers?.[0]?.label).toBe("SRE Runbook Agent");
  expect(result.edges.find(edge => edge.data?.originalRelationship === "hosted_on")).toMatchObject({ source: "container:copilot-portal", target: "agent:developer-copilot", data: { originalSource: "agent:developer-copilot", originalTarget: "container:copilot-portal", relationshipLabel: "Hosts" } });
  expect(result.edges.filter(edge => !edge.data?.displayOnly).every(edge => graph.edges.some(record => record.id === edge.id))).toBe(true);
  const pairs = new Set([...path.slice(1).map((id, index) => `${path[index]}>${id}`), "server:filesystem>tool:exec"]);
  for (const edge of result.edges) {
    expect(edge.style?.stroke === "var(--graph-edge-exposure)").toBe(pairs.has(`${edge.source}>${edge.target}`));
    if (edge.data?.exposurePath) expect(edge.style?.strokeDasharray).toBeUndefined();
    expect(edge.data?.quietLabel).toBe(true);
  }
  expect(JSON.stringify(graph)).toBe(original);
});

it("selects the identity entry separately while retaining principal access and modeled evidence", () => {
  const {graph, flow} = sample();
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {}, "identity");
  expect(result.nodes.some(node => ["display:internet", "container:copilot-portal"].includes(node.id))).toBe(false);
  const chain = ["sa:jit-review", "role:prod-admin", "agent:developer-copilot", "server:filesystem", "tool:exec"];
  for (let i = 1; i < chain.length; i++) expect(result.nodes.find(node => node.id === chain[i])!.position.x).toBeGreaterThan(result.nodes.find(node => node.id === chain[i - 1])!.position.x);
  expect(result.edges.find(edge => edge.data?.relationship === "can_access")).toMatchObject({source: "role:prod-admin", target: "agent:developer-copilot", style: {stroke: "var(--graph-edge-risk)", strokeDasharray: "6 3"}, data: {quietLabel: false}});
  expect(result.edges.some(edge => edge.data?.exposurePath)).toBe(false);
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

it("never upgrades modeled impact links or invents a critical asset classification", () => {
  const {graph, flow} = sample();
  const record = graph.edges.find(edge => edge.source === "server:filesystem" && edge.target === "tool:exec")!;
  record.evidence = {tier: "modeled_infrastructure"};
  flow.nodes.find(node => node.id === "cred:aws")!.data.attributes = {};
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  expect(result.edges.find(edge => edge.id === record.id)).toMatchObject({style: {strokeDasharray: "6 3"}, data: {evidenceMode: "inferred"}});
  expect(result.nodes.find(node => node.id === "cred:aws")!.data.attributes).toEqual({});
});

it("keeps the capability endpoint when another server has more findings, without overlapping disclosure groups", () => {
  const {graph, flow} = sample();
  const github = flow.nodes.find(node => node.id === "server:github")!;
  github.data.findingAggregate = {...counts.node_aggregates["server:filesystem"].aggregate, issue_count: 2};
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  expect(result.edges.find(edge => edge.target === "tool:exec")?.data?.exposurePath).toBe(true);
  expect(new Set(result.nodes.map(node => `${node.position.x},${node.position.y}`)).size).toBe(result.nodes.length);
});

it("draws recorded exposure as part of the selected path without persisting a new edge", () => {
  const {graph, flow} = sample();
  const result = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  const context = result.edges.find(edge => edge.source === "display:internet")!;
  expect(context.data).toMatchObject({displayOnly: true, traversable: false, exposurePath: true});
  expect(context.markerEnd).toBeDefined();
  expect(context.style?.strokeDasharray).toBeUndefined();
});
