import { describe, expect, it } from "vitest";

import { canvasNodeLabel, containerOccurrenceRole } from "@/lib/graph-occurrence-role";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createFocusedGraphFilters } from "@/components/lineage-filter";
import { EntityType, RelationshipType, type UnifiedGraphData, type UnifiedNode } from "@/lib/graph-schema";

const at = "2026-06-01T00:00:00Z";
const digest = "sha256:7d3e21c47d244111d7502503e9868ce01f2dfd77f0d71d876a3a8da1f477d58a";

function node(id: string, entityType: EntityType, label: string, dataSources: string[]): UnifiedNode {
  return {
    id, entity_type: entityType, label, category_uid: 0, class_uid: 0, type_uid: 0, status: "active",
    risk_score: 0, severity: "none", severity_id: 0, first_seen: at, last_seen: at, attributes: {},
    compliance_tags: [], data_sources: dataSources, dimensions: {},
  };
}

function contains(source: string): UnifiedGraphData["edges"][number] {
  return { id: `${source}-pkg`, source, target: "pkg", relationship: RelationshipType.CONTAINS, direction: "directed",
    weight: 1, traversable: true, first_seen: at, last_seen: at, evidence: {}, activity_id: 1 };
}

describe("container occurrence roles", () => {
  it("derives the role from the recorded collector, not the label", () => {
    expect(containerOccurrenceRole(["cyclonedx_sbom"])).toBe("Image inventory");
    expect(containerOccurrenceRole(["kubernetes_iac"])).toBe("Deployment occurrence");
    expect(containerOccurrenceRole(["kubernetes_iac", "cyclonedx_sbom"])).toBeUndefined();
    expect(containerOccurrenceRole(["test"])).toBeUndefined();
  });

  it("keeps the digest off the canvas label and in the full label", () => {
    expect(canvasNodeLabel(`reference-evidence-api@${digest}`)).toBe("reference-evidence-api");
    expect(canvasNodeLabel("pillow@9.0.0")).toBe("pillow@9.0.0");
  });

  it("labels same-image occurrences only when they would otherwise read as duplicates", () => {
    const graph = {
      scan_id: "s", tenant_id: "default", created_at: at, attack_paths: [], interaction_risks: [],
      nodes: [
        node("c-sbom", EntityType.CONTAINER, `reference-evidence-api@${digest}`, ["cyclonedx_sbom"]),
        node("c-k8s", EntityType.CONTAINER, `reference-evidence-api@${digest}`, ["kubernetes_iac"]),
        node("c-solo", EntityType.CONTAINER, "model-serving", ["cyclonedx_sbom"]),
        node("pkg", EntityType.PACKAGE, "pillow@9.0.0", ["cyclonedx_sbom"]),
      ],
      edges: [contains("c-sbom"), contains("c-k8s"), contains("c-solo")],
    } as unknown as UnifiedGraphData;
    const roles = Object.fromEntries(buildUnifiedFlowGraph(graph, { ...createFocusedGraphFilters(), layers: { ...createFocusedGraphFilters().layers, container: true, package: true } }).nodes.map((item) => [item.id, item.data.occurrenceRole]));
    expect(roles).toMatchObject({ "c-sbom": "Image inventory", "c-k8s": "Deployment occurrence", "c-solo": undefined });
  });
});

describe("same-name instance context", () => {
  it("shows the recorded config scope without recovering redacted filesystem paths", () => {
    const graph = {
      scan_id: "s", nodes: [
        node("agent:cfg-926bd270c907:reader", EntityType.AGENT, "Workspace reader", []),
        node("agent:cfg-a0fa3719e962:reader", EntityType.AGENT, "Workspace reader", []),
      ], edges: [], attack_paths: [], interaction_risks: [],
    } as unknown as UnifiedGraphData;
    const result = buildUnifiedFlowGraph(graph, createFocusedGraphFilters());
    expect(result.nodes.map((n) => n.data.identityContext)).toEqual(["Config 926bd270c907", "Config a0fa3719e962"]);
    expect(result.nodes.map((n) => n.data.label)).toEqual(["Workspace reader", "Workspace reader"]);
    expect(new Set(result.nodes.map((n) => n.id)).size).toBe(2);
  });
});

it("keeps same-config collisions distinct and hints stable when input order changes", () => {
  const nodes = [
    node("agent:cfg-926bd270c907:a", EntityType.AGENT, "reader", []),
    node("agent:cfg-926bd270c907:b", EntityType.AGENT, "reader", []),
    node("agent:solo", EntityType.AGENT, "single", []),
  ];
  const build = (items: UnifiedNode[]) => buildUnifiedFlowGraph({ nodes: items, edges: [], attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData, createFocusedGraphFilters()).nodes;
  const hints = (items: UnifiedNode[]) => Object.fromEntries(build(items).map((n) => [n.id, n.data.identityContext]));
  expect(hints(nodes)).toEqual(hints([...nodes].reverse()));
  expect(new Set(build(nodes).slice(0, 2).map((n) => n.data.identityContext)).size).toBe(2);
  expect(hints(nodes)["agent:solo"]).toBeUndefined();
});

it("does not turn unknown or redacted scope into an invented config path", () => {
  const graph = {
    nodes: [node("agent:opaque-one", EntityType.AGENT, "reader", []), node("agent:opaque-two", EntityType.AGENT, "reader", [])],
    edges: [], attack_paths: [], interaction_risks: [],
  } as unknown as UnifiedGraphData;
  const result = buildUnifiedFlowGraph(graph, createFocusedGraphFilters());
  const hints = result.nodes.map((n) => n.data.identityContext);
  expect(new Set(hints).size).toBe(2);
  for (const hint of hints) expect(hint).toMatch(/^Instance [a-f0-9]{8}$/);
});
