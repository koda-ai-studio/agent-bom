import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { declutterRelationshipLabels, hideRedundantDerivedEdges } from "@/lib/graph-label-declutter";

const edge = (source: string, target: string, relationship: string, label?: string): Edge => ({
  id: `${source}:${relationship}:${target}`, source, target, data: { relationship }, ...(label ? { label } : {}),
});

describe("declutterRelationshipLabels", () => {
  it("shows a six-way fan-out once with its count and keeps its qualifier", () => {
    const edges = Array.from({ length: 6 }, (_, i) => edge("agent", `role-${i}`, "can_access", "Can Access · configured"));
    const result = declutterRelationshipLabels(edges);
    const visible = result.filter(e => typeof e.label === "string");
    expect(visible.map(e => e.label)).toEqual(["Can Access ×6 · configured"]);
    expect(result.filter(e => e.data?.quietLabel === true)).toHaveLength(5);
  });

  it("keeps distinct relationships and qualifiers apart", () => {
    const result = declutterRelationshipLabels([
      edge("agent", "a", "uses", "Uses · configured"),
      edge("agent", "b", "uses", "Uses · observed"),
      edge("agent", "c", "can_access", "Can Access · configured"),
    ]);
    expect(result.map(e => e.label).sort()).toEqual(["Can Access · configured", "Uses · configured", "Uses · observed"]);
  });

  it("groups a fan-in by its shared target", () => {
    const result = declutterRelationshipLabels([edge("a", "server", "uses", "Uses"), edge("b", "server", "uses", "Uses"), edge("server", "pkg", "depends_on", "Depends On")]);
    expect(result.filter(e => typeof e.label === "string").map(e => e.label).sort()).toEqual(["Depends On", "Uses ×2"]);
  });

  it("leaves unlabelled and single edges untouched", () => {
    const edges = [edge("a", "b", "uses"), edge("b", "c", "uses", "Uses")];
    expect(declutterRelationshipLabels(edges)).toEqual(edges);
  });
});

const servers = (...ids: string[]): Node[] => ids.map(id => ({ id, position: { x: 0, y: 0 }, data: { nodeType: "server" } }));

describe("hideRedundantDerivedEdges", () => {
  it("hides shares_server when the shared server is drawn for both agents", () => {
    const edges = [edge("agent", "fs", "uses"), edge("peer", "fs", "uses"), edge("agent", "peer", "shares_server")];
    expect(hideRedundantDerivedEdges(edges, servers("fs")).map(e => e.id)).toEqual(["agent:uses:fs", "peer:uses:fs"]);
  });

  it("keeps shared risks when only an unrelated common account is visible", () => {
    const edges = [edge("account", "a", "contains"), edge("account", "b", "contains"), edge("a", "b", "shares_server")];
    expect(hideRedundantDerivedEdges(edges, servers("account"))).toEqual(edges);
  });

  it("does not substitute shared server use for shared credential evidence", () => {
    const edges = [edge("a", "fs", "uses"), edge("b", "fs", "uses"), edge("a", "b", "shares_cred")];
    expect(hideRedundantDerivedEdges(edges, servers("fs"))).toEqual(edges);
  });

  it("requires a visible server and outgoing uses links to that server", () => {
    const edges = [edge("a", "resource", "uses"), edge("b", "resource", "uses"), edge("a", "b", "shares_server")];
    expect(hideRedundantDerivedEdges(edges, [])).toEqual(edges);
    const account = { ...servers("resource")[0]!, data: { nodeType: "account" } };
    expect(hideRedundantDerivedEdges(edges, [account])).toEqual(edges);
    const reverse = [edge("resource", "a", "uses"), edge("resource", "b", "uses"), edges[2]!];
    expect(hideRedundantDerivedEdges(reverse, servers("resource"))).toEqual(reverse);
    const hidden = [edges[0]!, { ...edges[1]!, hidden: true }, edges[2]!];
    expect(hideRedundantDerivedEdges(hidden, servers("resource"))).toEqual(hidden);
  });

  it("keeps a correlation for a different recorded shared server", () => {
    const edges = [edge("a", "fs", "uses"), edge("b", "fs", "uses"), edge("a", "b", "shares_server")];
    const recorded = [{ id: edges[2]!.id, evidence: { server: "other-server" } }];
    expect(hideRedundantDerivedEdges(edges, servers("fs"), recorded)).toEqual(edges);
    expect(hideRedundantDerivedEdges(edges, servers("fs"), [{ ...recorded[0]!, evidence: { server: "fs" } }])).toHaveLength(2);
  });

  it("keeps shares_server when the shared resource is out of view", () => {
    const edges = [edge("agent", "github", "uses"), edge("agent", "peer", "shares_server")];
    expect(hideRedundantDerivedEdges(edges, servers("github"))).toHaveLength(2);
  });
});

describe("declutterRelationshipLabels with summarised links", () => {
  it("leaves cluster and aggregate links with their own counts", () => {
    const clustered = Array.from({ length: 3 }, (_, i) => ({ ...edge("pill", `pkg-${i}`, "contains", "22 members"), data: { relationship: "contains", isClusterEdge: true } }));
    expect(declutterRelationshipLabels(clustered).map(e => e.label)).toEqual(["22 members", "22 members", "22 members"]);
  });
});
