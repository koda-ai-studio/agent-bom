import { describe, expect, it } from "vitest";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import type { UnifiedGraphData } from "@/lib/graph-schema";

const node = (id: string, entity_type: string, attributes: Record<string, unknown> = {}) => ({ id, entity_type, label: id, attributes, dimensions: {}, severity: "none", data_sources: [] });
const edge = (source: string, target: string, relationship: string) => ({ id: `${source}:${relationship}:${target}`, source, target, relationship, evidence: { source: "configuration", tier: "declared" } });
function flow(nodes: ReturnType<typeof node>[], edges: ReturnType<typeof edge>[]) {
  return buildUnifiedFlowGraph({ nodes, edges, attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData, createExpandedGraphFilters());
}

describe("agent context in graph presentation", () => {
  it("keeps AWS environment membership distinct from an unknown execution host", () => {
    const graph = flow([node("agent", "agent", { agent_type: "workflow" }), node("env", "environment", { cloud_provider: "aws" })], [edge("env", "agent", "contains")]);
    expect(graph.edges[0]!.data?.relationshipLabel).toBe("Includes · membership");
    const agent = graph.nodes.find(n => n.id === "agent")!.data;
    expect(agent.agentContext).toMatchObject({ agentKind: "workflow", execution: { status: "not_recorded" }, membership: { items: [{ label: "env", provider: "aws" }] } });
  });
  it("separates a Claude client, EC2 host and separately recorded model", () => {
    const graph = flow([node("agent", "agent", { agent_type: "claude-code" }), node("vendor", "provider"), node("host", "cloud_resource", { cloud_provider: "aws", cloud_service: "ec2", scope: { account_id: "account-a" } }), node("model", "model", { cloud_provider: "gcp" })], [edge("vendor", "agent", "platform_for"), edge("agent", "host", "hosted_on"), edge("agent", "model", "serves_model")]);
    expect(graph.nodes.find(n => n.id === "agent")!.data.agentContext).toMatchObject({ agentKind: "claude-code", platforms: { items: [{ label: "vendor" }] }, execution: { items: [{ provider: "aws", service: "ec2", account_id: "account-a" }] }, models: { items: [{ provider: "gcp" }] } });
    expect(graph.nodes.find(n => n.id === "vendor")!.data.agentCount).toBe(1);
  });
  it("treats historical provider-hosts-agent edges as platform association", () => {
    const graph = flow([node("agent", "agent"), node("vendor", "provider")], [edge("vendor", "agent", "hosts")]);
    expect(graph.nodes.find(n => n.id === "agent")!.data.agentContext).toMatchObject({ execution: { status: "not_recorded" }, platforms: { items: [{ label: "vendor" }] } });
  });
});

import { render, screen } from "@testing-library/react";
import { PrimaryNodeDetails } from "@/components/lineage-detail/node-details";
it("shows missing hosting and model evidence separately in the inspector", () => {
  const graph = flow([node("agent", "agent", { agent_type: "workflow" }), node("env", "environment", { cloud_provider: "aws" })], [edge("env", "agent", "contains")]);
  render(<PrimaryNodeDetails data={graph.nodes.find(n => n.id === "agent")!.data} />);
  expect(screen.getByText("Execution host")).toBeInTheDocument();
  expect(screen.getByText("Model links")).toBeInTheDocument();
  expect(screen.getByText("Environment membership")).toBeInTheDocument();
  expect(screen.getByText(/Membership does not establish where/)).toBeInTheDocument();
});

it("counts one linked agent across historical and current platform edges", () => {
  const graph = flow([node("agent", "agent"), node("vendor", "provider")], [edge("vendor", "agent", "hosts"), edge("vendor", "agent", "platform_for")]);
  expect(graph.nodes.find(n => n.id === "vendor")!.data.agentCount).toBe(1);
});

it("preserves exact retained node identities and bounds displayed references", () => {
  const id = `cloud_resource:${"x".repeat(240)}`;
  const items = Array.from({ length: 20 }, (_, i) => ({ node_id: `${id}:${i}`, label: `Host ${i}`, relationship: "hosted_on", credential_value: "must-not-copy" }));
  const graph = flow([node("agent", "agent", { agent_context: { schema_version: "agent.context.v1", execution: { items, recorded_count: 20 } } })], []);
  const context = graph.nodes[0]!.data.agentContext;
  expect(context?.execution.items[0]?.node_id).toBe(`${id}:0`);
  expect(context?.execution.items).toHaveLength(16);
  expect(context?.execution.truncated).toBe(true);
  expect(JSON.stringify(context)).not.toContain("must-not-copy");
});

it("uses exact endpoint inventory binding without treating a logical fleet as a host", () => {
  const hostEdge = { ...edge("endpoint", "agent", "hosts"), evidence: { source: "endpoint_inventory", tier: "static_scan", identity_match_basis: "exact_source_id", execution_proven: false } };
  const graph = flow([node("agent", "agent"), node("endpoint", "fleet", { endpoint_id: "a" }), node("fleet", "fleet")], [hostEdge, edge("fleet", "agent", "hosts")]);
  expect(graph.nodes.find(n => n.id === "agent")!.data.agentContext?.execution.items.map(item => item.node_id)).toEqual(["endpoint"]);
});

import { buildFallbackNodeData } from "@/lib/graph-page-data";
it("retains loaded context when an investigation opens its root directly", () => {
  const agent = node("agent", "agent", { agent_type: "workflow" });
  const graph = { nodes: [agent, node("env", "environment"), node("platform", "provider")], edges: [edge("env", "agent", "contains"), edge("platform", "agent", "platform_for")] } as unknown as UnifiedGraphData;
  const data = buildFallbackNodeData(graph.nodes[0]!, graph);
  expect(data.agentContext?.platforms.items[0]?.node_id).toBe("platform");
  expect(data.agentContext?.membership.items[0]?.node_id).toBe("env");
  expect(data.agentContext?.execution.status).toBe("not_recorded");
});
