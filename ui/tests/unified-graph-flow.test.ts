import { describe, expect, it } from "vitest";

import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters, createFocusedGraphFilters, createInvestigationGraphFilters } from "@/components/lineage-filter";
import {
  EntityType,
  RelationshipType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
} from "@/lib/graph-schema";

const createdAt = "2026-06-01T00:00:00Z";

function node(id: string, entityType: EntityType, label: string, severity = "none"): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: severity === "critical" ? 9.4 : 0,
    severity,
    severity_id: severity === "critical" ? 5 : 0,
    first_seen: createdAt,
    last_seen: createdAt,
    attributes: {},
    compliance_tags: [],
    data_sources: ["test"],
    dimensions: {},
  };
}

function edge(source: string, target: string, relationship: RelationshipType): UnifiedEdge {
  return {
    id: `${source}->${relationship}->${target}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: createdAt,
    last_seen: createdAt,
    evidence: {},
    activity_id: 1,
  };
}

describe("buildUnifiedFlowGraph", () => {
  it("retains recorded assets without relationships in expanded topology", () => {
    const graph = {
      scan_id: "isolated-inventory", tenant_id: "default", created_at: createdAt,
      nodes: [node("a", EntityType.AGENT, "Planner"), node("s", EntityType.SERVER, "Tools"), node("m", EntityType.MODEL, "Recorded model")],
      edges: [edge("a", "s", RelationshipType.USES)], attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const filters = createExpandedGraphFilters();
    const flow = buildUnifiedFlowGraph(graph, filters);
    expect(flow.nodes.map(item => item.id)).toEqual(["a", "s", "m"]);
    expect(flow.edges).toHaveLength(1);
    expect(buildUnifiedFlowGraph(graph, { ...filters, layers: { ...filters.layers, model: false } }).nodes.map(item => item.id)).toEqual(["a", "s"]);
    expect(buildUnifiedFlowGraph(graph, { ...filters, agentName: "Planner" }).nodes.map(item => item.id)).toEqual(["a", "s"]);
  });

  it.each(["directed", "bidirectional"] as const)("preserves recorded %s arrow direction", (direction) => {
    const graph = {
      scan_id: "direction", tenant_id: "default", created_at: createdAt,
      nodes: [node("a", EntityType.AGENT, "Planner"), node("b", EntityType.AGENT, "Worker")],
      edges: [{ ...edge("a", "b", RelationshipType.SHARES_SERVER), direction }],
      attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const flow = buildUnifiedFlowGraph(graph, createFocusedGraphFilters());
    expect(flow.edges[0]?.markerEnd).toBeDefined();
    if (direction === "bidirectional") expect(flow.edges[0]?.markerStart).toEqual(flow.edges[0]?.markerEnd);
    else expect(flow.edges[0]?.markerStart).toBeUndefined();
  });

  it.each([
    { evidence: { source: "source-ast" }, mode: "static", count: 0 },
    { evidence: { basis: "configured_delegation" }, mode: "static", count: 0 },
    { evidence: {}, mode: "unknown", count: 0 },
    { evidence: { data_source: "runtime-proxy" }, mode: "runtime", count: 1 },
  ])("does not infer runtime delegation from the verb alone: $mode / $evidence", ({ evidence, mode, count }) => {
    const graph = {
      scan_id: "delegation", tenant_id: "default", created_at: createdAt,
      nodes: [node("a", EntityType.AGENT, "Planner"), node("b", EntityType.AGENT, "Worker")],
      edges: [{ ...edge("a", "b", RelationshipType.DELEGATED_TO), evidence }],
      attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const flow = buildUnifiedFlowGraph(graph, createFocusedGraphFilters());
    expect(flow.edges[0]?.data?.evidenceMode).toBe(mode);
    expect(flow.summary.runtimeEdges).toBe(count);
    if (mode !== "runtime") expect(flow.edges[0]?.animated).toBe(false);
  });

  it.each([
    { relationship: RelationshipType.CALLED, evidence: { source: "cloud-audit-trail", observed: true }, mode: "runtime", animated: true },
    { relationship: RelationshipType.CALLED, evidence: { source: "cloud-audit-trail" }, mode: "unknown", animated: false },
    { relationship: RelationshipType.CALLED, evidence: { source: "runtime-proxy", blocked: true }, mode: "runtime", animated: false },
    { relationship: RelationshipType.DELEGATED_TO, evidence: { evidence_tier: "configured" }, mode: "static", animated: false },
    { relationship: RelationshipType.VULNERABLE_TO, evidence: {}, mode: "unknown", animated: false },
  ])("aligns evidence and motion for $relationship / $evidence", ({ relationship, evidence, mode, animated }) => {
    const graph = { scan_id: "evidence", tenant_id: "default", created_at: createdAt,
      nodes: [node("a", EntityType.AGENT, "Planner"), node("b", EntityType.AGENT, "Worker")],
      edges: [{ ...edge("a", "b", relationship), evidence, weight: 9 }], attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData;
    const flow = buildUnifiedFlowGraph(graph, createFocusedGraphFilters());
    expect(flow.edges[0]?.data?.evidenceMode).toBe(mode);
    expect(flow.edges[0]?.animated).toBe(animated);
  });
  it("counts distinct loaded entities of the requested type, not relationship rows", () => {
    const nodes = [node("agent", EntityType.AGENT, "Agent"), node("server", EntityType.SERVER, "Server"), node("tool", EntityType.TOOL, "Tool")];
    const graph = {
      scan_id: "partial", tenant_id: "default", created_at: createdAt, nodes,
      edges: [edge("agent", "server", RelationshipType.USES), { ...edge("agent", "server", RelationshipType.USES), id: "second-receipt" }, edge("agent", "tool", RelationshipType.USES), edge("agent", "unloaded-server", RelationshipType.USES)],
      attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const data = buildUnifiedFlowGraph(graph, createFocusedGraphFilters(), new Set(nodes.map((item) => item.id))).nodes.find((item) => item.id === "agent")!.data;
    expect(data.serverCount).toBe(1);
    expect(data.countScope).toBe("loaded_graph");
    expect(data.countHopLimits).toEqual({ serverCount: 1, packageCount: 3, vulnCount: 5 });
  });

  it("does not traverse missing intermediate nodes when counting loaded descendants", () => {
    const nodes = [node("agent", EntityType.AGENT, "Agent"), node("package", EntityType.PACKAGE, "Package")];
    const graph = {
      scan_id: "partial", tenant_id: "default", created_at: createdAt, nodes,
      edges: [edge("agent", "missing", RelationshipType.USES), edge("missing", "package", RelationshipType.DEPENDS_ON)],
      attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const data = buildUnifiedFlowGraph(graph, createFocusedGraphFilters(), new Set(nodes.map((item) => item.id))).nodes.find((item) => item.id === "agent")!.data;
    expect(data.packageCount).toBe(0);
    expect(data.countScope).toBe("loaded_graph");
  });
  it("retains explicitly changed standalone resources without bypassing layer filters", () => {
    const graph = {
      scan_id: "scenario", tenant_id: "default", created_at: createdAt,
      nodes: [node("endpoint", EntityType.CLOUD_RESOURCE, "Private endpoint")],
      edges: [], attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const filters = createFocusedGraphFilters();
    filters.layers.cloudResource = true;
    expect(buildUnifiedFlowGraph(graph, filters).nodes.map((item) => item.id)).toEqual(["endpoint"]);
    const retained = new Set(["endpoint"]);
    expect(buildUnifiedFlowGraph(graph, filters, retained).nodes.map((item) => item.id)).toEqual(["endpoint"]);
    expect(buildUnifiedFlowGraph(graph, filters, retained).edges).toHaveLength(0);
    filters.layers.cloudResource = false;
    expect(buildUnifiedFlowGraph(graph, filters, retained).nodes).toHaveLength(0);
  });
  it("keeps agent and finding endpoints in focused relevant-path windows", () => {
    const graph: UnifiedGraphData = {
      scan_id: "scan-path",
      tenant_id: "default",
      created_at: createdAt,
      nodes: [
        node("agent:desktop", EntityType.AGENT, "Desktop Agent", "high"),
        node("server:filesystem", EntityType.SERVER, "filesystem MCP", "high"),
        node("pkg:filesystem", EntityType.PACKAGE, "filesystem-package", "high"),
        node("cve:filesystem", EntityType.VULNERABILITY, "CVE-2026-1001", "critical"),
      ],
      edges: [
        edge("agent:desktop", "server:filesystem", RelationshipType.USES),
        edge("server:filesystem", "pkg:filesystem", RelationshipType.DEPENDS_ON),
        edge("pkg:filesystem", "cve:filesystem", RelationshipType.VULNERABLE_TO),
      ],
      attack_paths: [
        {
          source: "agent:desktop",
          target: "cve:filesystem",
          hops: ["agent:desktop", "server:filesystem", "pkg:filesystem", "cve:filesystem"],
          edges: [],
          composite_risk: 9.4,
          summary: "Desktop Agent can reach a critical package vulnerability.",
          credential_exposure: [],
          tool_exposure: [],
          vuln_ids: ["CVE-2026-1001"],
        },
      ],
      interaction_risks: [],
      stats: {
        total_nodes: 4,
        total_edges: 3,
        node_types: {},
        severity_counts: {},
        relationship_types: {},
        attack_path_count: 1,
        interaction_risk_count: 0,
        max_attack_path_risk: 9.4,
        highest_interaction_risk: 0,
      },
    };

    const flow = buildUnifiedFlowGraph(graph, createFocusedGraphFilters("Desktop Agent"));
    expect(flow.nodes.map((entry) => entry.id).sort()).toEqual([
      "agent:desktop",
      "cve:filesystem",
      "pkg:filesystem",
      "server:filesystem",
    ]);
    expect(flow.summary).toMatchObject({ agents: 1, findings: 1, critical: 1 });
    expect(flow.edges.find((entry) => entry.id.includes("vulnerable_to"))?.data).toMatchObject({
      relationship: "vulnerable_to",
      relationshipLabel: "Has finding",
      evidenceMode: "unknown",
    });
  });

  it("retains application entities through the existing container renderer", () => {
    const graph: UnifiedGraphData = {
      scan_id: "scan-application",
      tenant_id: "default",
      created_at: createdAt,
      nodes: [
        node("agent:checkout", EntityType.AGENT, "Checkout Agent"),
        node("application:checkout", EntityType.APPLICATION, "Checkout"),
      ],
      edges: [
        edge(
          "agent:checkout",
          "application:checkout",
          RelationshipType.USES,
        ),
      ],
      attack_paths: [],
      interaction_risks: [],
      stats: {
        total_nodes: 2,
        total_edges: 1,
        node_types: { agent: 1, application: 1 },
        severity_counts: {},
        relationship_types: {},
        attack_path_count: 0,
        interaction_risk_count: 0,
        max_attack_path_risk: 0,
        highest_interaction_risk: 0,
      },
    };
    const filters = createFocusedGraphFilters();
    filters.layers.container = true;

    const flow = buildUnifiedFlowGraph(graph, filters);

    expect(flow.nodes).toHaveLength(2);
    expect(flow.nodes.find((entry) => entry.id === "application:checkout")).toMatchObject({
      id: "application:checkout",
      type: "containerNode",
      data: { nodeType: "container", entityType: "application" },
    });
  });
});

describe("cost summary", () => {
  function costGraph(attrs: Record<string, unknown>[]): UnifiedGraphData {
    const nodes = attrs.map((a, i) => ({
      ...node(`agent:a${i}`, EntityType.AGENT, `agent-${i}`),
      attributes: a as Record<string, never>,
    }));
    return {
      scan_id: "scan-cost",
      tenant_id: "default",
      created_at: createdAt,
      nodes,
      edges: [],
      attack_paths: [],
      interaction_risks: [],
      stats: {
        total_nodes: nodes.length,
        total_edges: 0,
        node_types: {},
        severity_counts: {},
        relationship_types: {},
        attack_path_count: 0,
        interaction_risk_count: 0,
        max_attack_path_risk: 0,
        highest_interaction_risk: 0,
        analysis_status: {},
      },
    } as unknown as UnifiedGraphData;
  }

  it("sums windowed spend across visible nodes", () => {
    const flow = buildUnifiedFlowGraph(
      costGraph([{ cost_usd_30d: 12.5 }, { cost_usd_30d: 7.25 }, {}]),
      createFocusedGraphFilters(""),
    );
    expect(flow.summary.costUsd30d).toBeCloseTo(19.75, 5);
  });

  it("counts nodes that are both expensive and exposed", () => {
    const flow = buildUnifiedFlowGraph(
      costGraph([
        { cost_usd_30d: 500, cost_risk_priority: "expensive_and_exposed" },
        { cost_usd_30d: 10 },
      ]),
      createFocusedGraphFilters(""),
    );
    expect(flow.summary.expensiveExposed).toBe(1);
  });

  it("reports zero when no node carries cost, so the strip stays hidden", () => {
    const flow = buildUnifiedFlowGraph(costGraph([{}, {}]), createFocusedGraphFilters(""));
    expect(flow.summary.costUsd30d).toBe(0);
    expect(flow.summary.expensiveExposed).toBe(0);
  });

  it("ignores a non-numeric cost attribute rather than rendering NaN", () => {
    const flow = buildUnifiedFlowGraph(
      costGraph([{ cost_usd_30d: "not-a-number" }, { cost_usd_30d: 5 }]),
      createFocusedGraphFilters(""),
    );
    expect(flow.summary.costUsd30d).toBe(5);
  });
});


describe("explicit investigation context", () => {
  it("shows the returned containment chain after leaving a finding-only lens", () => {
    const graph = { scan_id: "bounded", tenant_id: "default", created_at: createdAt,
      nodes: [node("account:root", EntityType.ACCOUNT, "Account"), node("env:prod", EntityType.ENVIRONMENT, "Production")],
      edges: [edge("account:root", "env:prod", RelationshipType.CONTAINS)], attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const previous = { ...createFocusedGraphFilters(), vulnOnly: true, severity: "critical" };
    expect(buildUnifiedFlowGraph(graph, previous).nodes).toHaveLength(0);
    const context = createInvestigationGraphFilters(previous);
    expect(buildUnifiedFlowGraph(graph, context).nodes.map(n => n.id)).toEqual(["account:root", "env:prod"]);
    expect(previous.vulnOnly).toBe(true);
    // A subsequent deliberate filter still takes effect; no invisible bypass.
    expect(buildUnifiedFlowGraph(graph, { ...context, vulnOnly: true }).nodes).toHaveLength(0);
  });
});

it.each([false, true])("preserves explicit risk assessment through the flow adapter (assessed=%s)", assessed => {
  const agent = node("agent", EntityType.AGENT, "Agent");
  if (assessed) agent.risk_assessment = { status: "assessed", basis: "test", scope: "node" };
  const graph = { scan_id: "assessment", tenant_id: "default", created_at: createdAt, nodes: [agent], edges: [], attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData;
  const data = buildUnifiedFlowGraph(graph, createFocusedGraphFilters(), new Set([agent.id])).nodes[0]!.data;
  expect(data.riskScore).toBe(0);
  expect(data.riskAssessment?.status).toBe(assessed ? "assessed" : "not_assessed");
});

it("preserves same-named assets across every catalogued vendor and keeps only recorded cross-vendor links", async () => {
  const { readFileSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const coverage = JSON.parse(readFileSync(resolve(__dirname, "../../docs/VENDOR_COVERAGE.json"), "utf8"));
  const providers = [...new Set<string>([...coverage.cloud_matrix.rows.map((row: { provider: string }) => row.provider), "okta", "supabase", "vercel", "langfuse", "langsmith"])];
  const nodes = providers.flatMap(provider => ["account-a", "account-b"].map(account => ({
    ...node(`${provider}:${account}:workload`, EntityType.CONTAINER, "production-api"),
    attributes: { cloud_provider: provider, account_id: account },
    dimensions: { cloud_provider: provider, account_id: account },
  })));
  const edges = [
    { ...edge(nodes[0]!.id, nodes[2]!.id, RelationshipType.DEPENDS_ON), evidence: { tier: "static_scan", source: "synthetic-config" } },
    { ...edge(nodes[2]!.id, nodes[0]!.id, RelationshipType.DEPENDS_ON), evidence: {} },
  ];
  const graph = { scan_id: "vendor-scopes", tenant_id: "tenant-a", created_at: createdAt, nodes, edges, attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData;
  const flow = buildUnifiedFlowGraph(graph, createInvestigationGraphFilters(createFocusedGraphFilters()), new Set(nodes.map(n => n.id)));
  expect(flow.nodes.map(n => n.id).sort()).toEqual(nodes.map(n => n.id).sort());
  expect(flow.edges.map(e => [e.id, e.source, e.target, e.data?.relationship])).toEqual(edges.map(e => [e.id, e.source, e.target, e.relationship]));
  expect(flow.edges.map(e => e.data?.evidenceLabel)).toEqual(["Static / configured", "Not recorded"]);
  expect(flow.nodes.every(n => n.data.identityContext)).toBe(true);
  expect(graph.edges).toEqual(edges);
});
