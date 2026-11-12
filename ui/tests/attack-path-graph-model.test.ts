import { describe, expect, it } from "vitest";

import { attackPathEvidenceGraph, buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { branchingFixture, edge, fanOutFixture, node, path } from "./fixtures/attack-path-graph-fixture";

describe("attack path graph model", () => {
  it("ends the path at the asset at risk and folds its findings into a badge", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const ids = model.nodes.map(item => item.id);
    expect(ids).not.toContain("cve:next");
    expect(ids).not.toContain("cve:next-2");
    const pkg = model.nodes.find(item => item.id === "pkg:next")!;
    expect(pkg.role).toBe("target");
    // Both recorded findings on the package, not only the one the path names.
    expect(pkg.findings.map(finding => finding.id)).toEqual(["cve:next", "cve:next-2"]);
    expect(pkg.findings[0]!.severity).toBe("critical");
    expect(model.nodes.find(item => item.id === "user:contractor")!.role).toBe("entry");
    expect(model.pathNodeIds).toEqual(["user:contractor", "sa:jit", "role:admin", "agent:copilot", "server:github", "pkg:next"]);
  });

  it("badge counts equal the distinct finding nodes recorded on each asset", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    for (const item of model.nodes) {
      const recorded = new Set(graph.edges.flatMap(link => {
        const other = link.source === item.id ? link.target : link.target === item.id ? link.source : null;
        const otherNode = graph.nodes.find(candidate => candidate.id === other);
        return otherNode?.entity_type === "vulnerability" ? [otherNode.id] : [];
      }));
      expect(item.findings).toHaveLength(item.kind === "group" ? item.findings.length : recorded.size);
    }
    expect(model.nodes.find(item => item.id === "pkg:urllib3")!.findings).toHaveLength(1);
  });

  it("branches off a shared node only along recorded edges to other paths in the snapshot", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const branch = model.nodes.filter(item => item.role === "branch").map(item => item.id).sort();
    expect(branch).toEqual(["agent:sre", "dataset:finance", "pkg:urllib3", "server:filesystem"]);
    expect(model.nodes.map(item => item.id)).not.toContain("agent:unrelated");
    const graphEdgeIds = new Set(graph.edges.map(link => link.id));
    for (const link of model.edges) expect(graphEdgeIds.has(link.id)).toBe(true);
    expect(model.edges.find(link => link.source === "agent:copilot" && link.target === "server:filesystem")?.onPath).toBe(false);
    expect(model.connectedPathCount).toBe(2);
  });

  it("draws no branches when no other path touches the selected one", () => {
    const { graph, selected } = branchingFixture();
    const isolated = { ...graph, attack_paths: [selected] };
    const model = buildAttackPathGraphModel(isolated, selected);
    expect(model.nodes.every(item => item.role !== "branch")).toBe(true);
    expect(model.connectedPathCount).toBe(0);
  });

  it("collapses more than three same-type siblings into one count node and expands on request", () => {
    const { graph, selected } = fanOutFixture(5);
    const collapsed = buildAttackPathGraphModel(graph, selected);
    const group = collapsed.nodes.find(item => item.kind === "group")!;
    expect(group).toMatchObject({ count: 5, parentId: "server:s" });
    expect(group.label).toBe("5 cloud resources");
    expect(collapsed.nodes.filter(item => item.id.startsWith("endpoint:"))).toHaveLength(0);
    expect(collapsed.edges.some(link => link.source === "server:s" && link.target === group.id)).toBe(true);

    const expanded = buildAttackPathGraphModel(graph, selected, { expandedGroups: new Set([group.id]) });
    expect(expanded.nodes.filter(item => item.id.startsWith("endpoint:"))).toHaveLength(5);
    expect(expanded.nodes.some(item => item.kind === "group")).toBe(false);
  });

  it("keeps three siblings visible", () => {
    const { graph, selected } = fanOutFixture(3);
    const model = buildAttackPathGraphModel(graph, selected);
    expect(model.nodes.filter(item => item.id.startsWith("endpoint:"))).toHaveLength(3);
    expect(model.nodes.some(item => item.kind === "group")).toBe(false);
  });

  it("derives context markers only from recorded attributes", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const markers = (id: string) => model.nodes.find(item => item.id === id)!.markers.map(marker => marker.kind);
    expect(markers("server:github")).toEqual(["internet"]);
    expect(markers("role:admin")).toEqual(["privileged"]);
    expect(markers("dataset:finance")).toEqual(["sensitive"]);
    // "unknown" is not proof of exposure.
    expect(markers("server:filesystem")).toEqual([]);
    expect(markers("user:contractor")).toEqual([]);
    expect(model.nodes.some(item => /internet/i.test(item.label))).toBe(false);
  });

  it("treats a 'none' sensitivity verdict and an explicit false exposure as no marker", () => {
    const graph = {
      scan_id: "s", tenant_id: "t", created_at: "", interaction_risks: [], stats: {},
      nodes: [node("a", "agent", "a", { internet_exposed: "false" }), node("d", "dataset", "d", { data_sensitivity: "none", privilege_level: "read" })],
      edges: [edge("a", "d", "accessed")],
      attack_paths: [],
    } as never;
    const selected = path(["a", "d"], ["accessed"]);
    const model = buildAttackPathGraphModel(graph, selected);
    expect(model.nodes.flatMap(item => item.markers)).toEqual([]);
  });

  it("classifies line style from the edge's own evidence envelope", () => {
    const { graph, selected } = branchingFixture();
    const model = buildAttackPathGraphModel(graph, selected);
    const evidence = (source: string, target: string) => model.edges.find(link => link.source === source && link.target === target)!.evidence;
    expect(evidence("user:contractor", "sa:jit")).toBe("recorded");
    expect(evidence("role:admin", "agent:copilot")).toBe("inferred");
    expect(evidence("server:github", "pkg:next")).toBe("unrecorded");
    expect(model.edges.find(link => link.source === "user:contractor")!.relationshipLabel).toMatch(/acted as/i);
  });

  it("keeps a finding that sits mid-path as a node so the chain is not broken", () => {
    const graph = {
      scan_id: "s", tenant_id: "t", created_at: "", interaction_risks: [], stats: {},
      nodes: [node("a", "agent", "a"), node("m", "misconfiguration", "open-bucket", {}, "high"), node("d", "dataset", "d")],
      edges: [edge("a", "m", "has_finding"), edge("m", "d", "exposes")],
      attack_paths: [],
    } as never;
    const model = buildAttackPathGraphModel(graph, path(["a", "m", "d"], ["has_finding", "exposes"]));
    expect(model.pathNodeIds).toEqual(["a", "m", "d"]);
  });
});

describe("attack path evidence graph", () => {
  it("holds every drawable node and its findings, and only recorded edges between them", () => {
    const { graph, selected } = fanOutFixture(5);
    const evidence = attackPathEvidenceGraph(graph, selected);
    const ids = evidence.nodes.map(item => item.id);
    expect(ids).toEqual(expect.arrayContaining(["agent:a", "server:s", "pkg:p", "cve:p", "endpoint:0", "endpoint:4"]));
    for (const link of evidence.edges) expect(graph.edges).toContainEqual(link);
    expect(evidence.attack_paths).toEqual([selected]);
  });
});
