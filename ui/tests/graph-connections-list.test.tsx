import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { GraphConnectionsList } from "@/components/graph-connections-list";
import type { LineageNodeData } from "@/components/lineage-nodes";

const node = (id: string, nodeType: string, label = id): Node<LineageNodeData> =>
  ({ id, position: { x: 0, y: 0 }, data: { label, nodeType } as LineageNodeData });
const edge = (source: string, target: string, relationship: string): Edge =>
  ({ id: `${source}:${relationship}:${target}`, source, target, data: { relationship, evidenceMode: "static" } });

describe("GraphConnectionsList", () => {
  it("lists a collapsed group's members individually with their evidence", () => {
    const servers = Array.from({ length: 6 }, (_, i) => node(`server-${i}`, "server", `Server ${i}`));
    const memberEdges = servers.map(server => edge("agent", server.id, "can_access"));
    const pill = { ...node("cluster:agent:server", "server", "+6 servers"), data: { label: "+6 servers", nodeType: "server", isCluster: true, memberEdges } as unknown as LineageNodeData };
    const onSelect = vi.fn();
    render(<GraphConnectionsList rootId="agent" nodes={[node("agent", "agent", "Developer Copilot"), pill]}
      edges={[{ id: "c", source: "agent", target: pill.id, data: { relationship: "can_access", isClusterEdge: true } }]}
      memberNodes={new Map([node("agent", "agent", "Developer Copilot"), ...servers].map(n => [n.id, n]))} onSelect={onSelect} />);
    expect(screen.getByText(/Can Access · configured · 6/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Server \d/ })).toHaveLength(6);
    expect(screen.queryByText("+6 servers")).not.toBeInTheDocument();
    screen.getByRole("button", { name: /Server 3/ }).click();
    expect(onSelect).toHaveBeenCalledWith("server-3");
  });
});
