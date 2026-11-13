import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphHierarchyLayout } from "@/lib/graph-hierarchy-layout";
import { mcpNodeCaption } from "@/lib/graph-mcp-caption";
import { findingEvidenceContext, MCP_FLOW_FOOTPRINT, mcpEvidenceFlow } from "@/lib/graph-mcp-flow";

const node = (id: string, nodeType: LineageNodeData["nodeType"], label = id): Node<LineageNodeData> => ({
  id, type: `${nodeType}Node`, position: { x: 0, y: 0 }, data: { label, nodeType },
});
const nodes = [node("client", "agent", "Claude Desktop"), node("github-1", "server", "github"),
  node("github-2", "server", "github"), node("files-1", "server", "filesystem"), node("files-2", "server", "filesystem"),
  node("github-package", "package", "@modelcontextprotocol/server-github@2025.4.8"),
  node("files-package", "package", "@modelcontextprotocol/server-filesystem@2.0.1"),
  node("credential", "credential", "GITHUB_PERSONAL_ACCESS_TOKEN"), node("finding", "misconfiguration", "Agent can reach a credential")];
const edges: Edge[] = [["client", "github-1", "uses"], ["client", "files-1", "uses"],
  ["github-1", "github-package", "depends_on"], ["github-2", "github-package", "depends_on"],
  ["files-1", "files-package", "depends_on"], ["files-2", "files-package", "depends_on"],
  ["github-1", "credential", "uses_credential"], ["credential", "finding", "exposed_to"],
  ["client", "finding", "exposed_to"]].map(([source, target, relationship], i) => ({
    id: `edge-${i}`, source: source!, target: target!, data: { relationship, evidenceMode: "inferred" },
  }));

describe("small MCP evidence flow", () => {
  it("keeps unlinked server occurrences in the server column without merging their identities", () => {
    const result = graphHierarchyLayout(nodes, edges);
    const at = Object.fromEntries(result.nodes.map(n => [n.id, n.position]));
    expect(new Set([at["github-1"]!.x, at["github-2"]!.x, at["files-1"]!.x, at["files-2"]!.x]).size).toBe(1);
    expect(at.client!.x).toBeLessThan(at["github-2"]!.x);
    expect(at["github-2"]!.x).toBeLessThan(at.credential!.x);
    expect(at.credential!.x).toBeLessThan(at.finding!.x);
    expect(result.nodes.map(n => n.id)).toEqual(nodes.map(n => n.id));
    expect(result.nodes.map(n => n.type)).toEqual(nodes.map(n => n.type));
    expect(result.edges.map(e => [e.id, e.source, e.target, e.data?.relationship]))
      .toEqual(edges.map(e => [e.id, e.source, e.target, e.data?.relationship]));
    const servers = result.nodes.filter(n => n.data.nodeType === "server");
    expect(servers.find(n => n.id === "github-1")!.data.evidenceFlowContext).toBe("Client: Claude Desktop");
    expect(servers.find(n => n.id === "github-2")!.data.evidenceFlowContext).toBe("Client link not recorded");
    for (const a of servers) for (const b of servers) if (a.id !== b.id) {
      expect(Math.abs(a.position.y - b.position.y)).toBeGreaterThanOrEqual(Number(a.style?.height ?? 0) + 24);
    }
  });

  it("aligns the finding evidence chain before supporting inventory branches", () => {
    const result = mcpEvidenceFlow(nodes, edges)!;
    const at = Object.fromEntries(result.nodes.map(n => [n.id, n.position]));
    expect(at.client!.y).toBe(at["github-1"]!.y);
    expect(at.credential!.y).toBe(at.client!.y);
    expect(at.finding!.y).toBe(at.client!.y);
    expect(at["github-package"]!.y).not.toBe(at.credential!.y);
    expect(at["files-1"]!.y).toBeGreaterThan(at["github-1"]!.y);
    const backwards = mcpEvidenceFlow(nodes, [{ id: "back", source: "finding", target: "credential", data: { relationship: "affects" } }])!;
    expect(backwards.edges[0]!.sourceHandle).toBe("context");
    expect(backwards.edges[0]!.targetHandle).toBe("context");
  });

  it("spaces rows for the tallest card it draws, so no two cards in a column overlap", () => {
    const result = mcpEvidenceFlow(nodes, edges)!;
    // Cards render 203-272px tall (glyph, a three-line name, metadata and the client line).
    expect(MCP_FLOW_FOOTPRINT.cardMaxHeight).toBeGreaterThanOrEqual(272);
    const box = (n: Node<LineageNodeData>) => ({ left: n.position.x, right: n.position.x + Number(n.style?.width ?? 0),
      top: n.position.y, bottom: n.position.y + MCP_FLOW_FOOTPRINT.cardMaxHeight });
    const overlaps: string[] = [];
    for (const [i, a] of result.nodes.entries()) for (const b of result.nodes.slice(i + 1)) {
      const p = box(a), q = box(b);
      if (p.left < q.right && q.left < p.right && p.top < q.bottom + 16 && q.top < p.bottom + 16) overlaps.push(`${a.id} / ${b.id}`);
    }
    expect(overlaps).toEqual([]);
  });

  it("balances connected branches above and below the primary evidence chain", () => {
    const result = mcpEvidenceFlow(nodes, edges)!;
    const primary = result.nodes.find(n => n.id === "client")!.position.y;
    const branchRows = result.nodes.filter(n => n.data.nodeType === "server").map(n => n.position.y);
    expect(Math.min(...branchRows)).toBeLessThan(primary);
    expect(Math.max(...branchRows)).toBeGreaterThan(primary);
    const low = Math.min(...result.nodes.map(n => n.position.y)), high = Math.max(...result.nodes.map(n => n.position.y));
    expect((primary - low) / (high - low)).toBeGreaterThanOrEqual(0.3);
    expect((primary - low) / (high - low)).toBeLessThanOrEqual(0.7);
  });

  it("is deterministic across API ordering and does not relabel scope or evidence", () => {
    const first = graphHierarchyLayout(nodes, edges);
    const reversed = graphHierarchyLayout([...nodes].reverse(), [...edges].reverse());
    expect(Object.fromEntries(first.nodes.map(n => [n.id, n.position])))
      .toEqual(Object.fromEntries(reversed.nodes.map(n => [n.id, n.position])));
    for (const n of first.nodes) expect(n.data.label).toBe(nodes.find(original => original.id === n.id)!.data.label);
    expect(first.edges.every(e => e.data?.evidenceMode === "inferred")).toBe(true);
  });

  it("traces recorded upstream finding evidence while leaving unrelated servers outside the highlight", () => {
    const layout = mcpEvidenceFlow(nodes, edges)!;
    expect(findingEvidenceContext("finding", layout.nodes, layout.edges))
      .toEqual(new Set(["finding", "credential", "github-1", "client"]));
    expect(findingEvidenceContext("github-1", layout.nodes, layout.edges)).toBeNull();
    const reverse = [...edges.filter(e => e.target !== "finding"),
      { id: "affects", source: "finding", target: "credential", data: { relationship: "affects" } },
      { id: "unrelated", source: "files-2", target: "finding", data: { relationship: "correlates_with" } }];
    expect(findingEvidenceContext("finding", layout.nodes, reverse))
      .toEqual(new Set(["finding", "credential", "github-1", "client"]));
  });

  it("leaves mixed infrastructure and crowded columns with the existing layout", () => {
    expect(mcpEvidenceFlow([...nodes, node("cloud", "cloudResource")], edges)).toBeNull();
    expect(mcpEvidenceFlow([...nodes, node("fifth-server", "server")], edges)).toBeNull();
  });
});


it("uses a compact prose finding caption without altering evidence or advisory identifiers", () => {
  const data: LineageNodeData = { label: "AI agent can reach a credential or privileged tool through a configured MCP server", nodeType: "misconfiguration", severity: "high" };
  expect(mcpNodeCaption(data, data.label).title).toBe("AI agent can reach a credential or privileged tool…");
  expect(data.label).toContain("through a configured MCP server");
  expect(mcpNodeCaption({ ...data, nodeType: "vulnerability" }, "CVE-2025-29927").title).toBe("CVE-2025-29927");
});
