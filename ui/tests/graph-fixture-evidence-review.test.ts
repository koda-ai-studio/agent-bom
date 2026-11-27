import { expect, it } from "vitest";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { nodeAggregatesResponse, scopeFindingsResponse } from "../scripts/product-proof-rollup.mjs";

it("assigns synthetic scan evidence consistently across all configuration and inventory relationships", () => {
  const graph = buildGraph();
  const recorded = new Set(["hosts", "hosted_on", "uses", "provides_tool", "exposes_cred", "depends_on", "vulnerable_to"]);
  for (const edge of graph.edges) {
    // An access grant read from an IAM policy by cloud inventory is configuration, so it is static too.
    const configured = recorded.has(edge.relationship) || (edge.relationship === "can_access" && (edge.evidence as Record<string, unknown>).basis === "iam_policy_grant" && edge.evidence.source === "synthetic-cloud-inventory");
    expect(edge.evidence, edge.id).toMatchObject({tier: configured ? "static_scan" : "modeled_infrastructure", simulated: true});
  }
  for (const path of graph.attack_paths) for (const [index, hop] of path.hop_evidence.entries()) {
    const edge = graph.edges.find(edge => edge.source === path.hops[index] && edge.target === path.hops[index + 1])!;
    expect(hop.evidence_tier, edge.id).toBe(edge.evidence.tier);
  }
});

it("offers the exposed portal's recorded dependency route independently of the identity route", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const route = graph.attack_paths.find(path => path.source === "container:copilot-portal" && path.target === "cve:next");
  expect(route).toBeDefined();
  expect(route!.hops).toEqual(["container:copilot-portal", "pkg:next", "cve:next"]);
  const model = buildAttackPathGraphModel(graph, route!);
  expect(model.nodes.map(node => node.label)).toEqual(expect.arrayContaining(["Internet", "copilot-portal:2.4.0", "next@15.2.2", "CVE-2025-29927"]));
  expect(model.nodes.some(node => node.id === "role:prod-admin")).toBe(false);
  expect(graph.attack_paths.some(path => path.source === "user:contractor")).toBe(true);
});

it("discloses the shared CVE at the descendant server once, preserving full scope totals", () => {
  const response = nodeAggregatesResponse(new URL("http://fixture?node_id=agent%3Adeveloper-copilot&node_id=server%3Afilesystem"));
  const root = response.aggregates.find(row => row.node_id === "agent:developer-copilot")!;
  const server = response.aggregates.find(row => row.node_id === "server:filesystem")!;
  expect(root.aggregate.issue_count).toBe(1);
  expect(root.finding_disclosure.issue_count).toBe(0);
  expect(server.finding_disclosure).toMatchObject({issue_count: 1, severity_counts: {medium: 1}});
  expect(scopeFindingsResponse(new URL("http://fixture?node_id=agent%3Adeveloper-copilot&exclude_node_id=server%3Afilesystem")).total).toBe(0);
});

it("shows a hosted agent as connected context without adding it to the vulnerability hops", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const route = graph.attack_paths.find(path => path.source === "container:copilot-portal")!;
  const model = buildAttackPathGraphModel(graph, route);
  expect(model.nodes.find(node => node.id === "agent:developer-copilot")).toMatchObject({role: "branch"});
  expect(model.pathNodeIds).not.toContain("agent:developer-copilot");
  const recorded = graph.edges.find(edge => edge.relationship === "hosted_on" && edge.source === "agent:developer-copilot")!;
  expect(model.edges.find(edge => edge.id === recorded.id)).toMatchObject({source: recorded.target, target: recorded.source, relationship: "hosts", onPath: false});
  expect(model.edges.find(edge => edge.source === "display:internet")).toMatchObject({displayOnly: true, evidence: "recorded", onPath: true});
});

it("paginates node-focused paths using path totals, never graph node totals", async () => {
  const {queryStaticAttackPaths} = await import("@/lib/static-demo-attack-paths.mjs");
  const graph = buildGraph();
  const matching = graph.attack_paths.filter(path => path.hops.includes("server:filesystem"));
  const result = queryStaticAttackPaths(graph, "/v1/graph/attack-paths?node_id=server%3Afilesystem&limit=1");
  expect(result.pagination).toMatchObject({total: matching.length, limit: 1, has_more: matching.length > 1});
  expect(result.attack_paths).toEqual(matching.slice(0,1));
  expect(queryStaticAttackPaths(graph, "/v1/graph/attack-paths?node_id=missing").pagination.total).toBe(0);
  expect(queryStaticAttackPaths(graph, "/v1/graph/attack-paths").pagination.total).toBe(graph.attack_paths.length);
});

it("derives demo fix guidance and totals without invented runtime claims", async () => {
  const { fixFirstView } = await import("../scripts/capture-product-proof.mjs");
  const graph = buildGraph();
  const response = fixFirstView();
  expect(response.cards).toHaveLength(graph.attack_paths.length);
  expect(response.summary.total_paths).toBe(graph.attack_paths.length);
  expect(response.cards.every(card => typeof card.title === "string" && card.title.length > 0)).toBe(true);
  expect(response.cards.flatMap(card => card.risk_reasons).some(reason => reason.kind === "runtime_policy")).toBe(false);
});

it("filters advisory and occurrence aliases without returning unrelated paths", async () => {
  const {queryStaticAttackPaths} = await import("@/lib/static-demo-attack-paths.mjs");
  const graph = buildGraph();
  const expected = graph.attack_paths.filter(path => path.vuln_ids.includes("CVE-2025-29927"));
  expect(queryStaticAttackPaths(graph, "/v1/graph/attack-paths?finding_id=cve-2025-29927").attack_paths).toEqual(expected);
  expect(queryStaticAttackPaths(graph, "/v1/graph/attack-paths?advisory_id=CVE-2025-29927").attack_paths).toEqual(expected);
  expect(queryStaticAttackPaths(graph, "/v1/graph/attack-paths?finding_id=occurrence&advisory_id=CVE-2025-29927&node_id=server%3Afilesystem").pagination.total).toBe(0);
});
