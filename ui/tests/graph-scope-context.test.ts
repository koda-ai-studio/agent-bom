import { describe, expect, it } from "vitest";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import { assignScopeContext, showsEnvironmentChip, showsProviderMark } from "@/lib/graph-scope-context";

type Fixture = { id: string; data: LineageNodeData };
const node = (id: string, nodeType: LineageNodeType, provider?: string, environment?: string, attributes: Record<string, unknown> = {}): Fixture => ({
  id,
  data: {
    label: id, nodeType,
    dimensions: { ...(provider ? { cloud_provider: provider } : {}), ...(environment ? { environment } : {}) },
    attributes,
  } as LineageNodeData,
});
const edge = (source: string, target: string, relationship: string) => ({ source, target, relationship });

function visible(nodes: Fixture[], edges: ReturnType<typeof edge>[]) {
  assignScopeContext(nodes, edges);
  const byId = Object.fromEntries(nodes.map((item) => [item.id, item.data]));
  return {
    marks: nodes.filter((item) => showsProviderMark(item.data)).map((item) => item.id),
    envs: nodes.filter((item) => showsEnvironmentChip(item.data)).map((item) => item.id),
    byId,
  };
}

// The owner's investigation canvas: one AWS account, an EKS cluster and its workloads.
function cloudCanvas() {
  const nodes = [
    node("account", "account", "aws"),
    node("gateway", "apiGateway", "aws", "production"),
    node("cluster", "cluster", "aws", "production"),
    node("checkout", "container", "aws", "production", { cloud_provider_basis: "inherited:hosts" }),
    node("ledger", "container", "aws", "staging", { cloud_provider_basis: "inherited:hosts" }),
    node("role", "role", "aws"),
    node("bucket", "dataStore", "aws", "production"),
    node("cve", "vulnerability"),
    node("finding", "misconfiguration"),
  ];
  const edges = [
    edge("account", "gateway", "contains"), edge("account", "cluster", "contains"),
    edge("cluster", "checkout", "hosts"), edge("cluster", "ledger", "hosts"),
    edge("gateway", "checkout", "exposed_to"), edge("checkout", "cve", "vulnerable_to"),
    edge("checkout", "role", "authenticates_as"), edge("role", "bucket", "has_permission"),
    edge("finding", "role", "affects"),
  ];
  return { nodes, edges };
}

describe("graph scope context", () => {
  it("shows the vendor mark once, on the scope root, in a single-vendor graph", () => {
    const { nodes, edges } = cloudCanvas();
    expect(visible(nodes, edges).marks).toEqual(["account"]);
  });

  it("marks only the cross-vendor hop in a mixed AWS and Snowflake graph", () => {
    const { nodes, edges } = cloudCanvas();
    nodes.push(node("warehouse", "cloudResource", "snowflake", "production"), node("table", "dataStore", "snowflake", "production"));
    edges.push(edge("role", "warehouse", "can_access"), edge("warehouse", "table", "contains"));
    expect(visible(nodes, edges).marks).toEqual(["account", "warehouse"]);
  });

  it("shows a vendor mark when the parents disagree", () => {
    const nodes = [node("aws", "account", "aws"), node("gcp", "account", "gcp"), node("shared", "cloudResource", "aws")];
    const edges = [edge("aws", "shared", "contains"), edge("gcp", "shared", "contains")];
    expect(visible(nodes, edges).marks).toEqual(["aws", "gcp", "shared"]);
  });

  it("shows the environment once at scope level and only where a node differs", () => {
    const { nodes, edges } = cloudCanvas();
    expect(visible(nodes, edges).envs).toEqual(["cluster", "ledger"]);
  });

  it("keeps every chip when no scope context was computed", () => {
    const lone = node("bucket", "dataStore", "aws", "production");
    expect(showsProviderMark(lone.data)).toBe(true);
    expect(showsEnvironmentChip(lone.data)).toBe(true);
  });

  it("keeps the environment on each root when no scope node anchors the canvas", () => {
    const nodes = [node("agent", "agent", undefined, "production"), node("server", "server", undefined, "production")];
    const edges = [edge("agent", "server", "uses")];
    expect(visible(nodes, edges).envs).toEqual(["agent"]);
  });
});
