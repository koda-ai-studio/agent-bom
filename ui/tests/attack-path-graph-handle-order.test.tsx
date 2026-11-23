import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { expect, it } from "vitest";
import { AttackPathGraphNode } from "@/components/attack-path-graph-node";
import type { PathGraphNode } from "@/lib/attack-path-graph-model";

it("renders the reading-order handles first, so an edge without a handle id leaves right and arrives left", () => {
  // xyflow resolves a missing handle id to the first measured handle of that type.
  const node: PathGraphNode = { id: "cred", kind: "entity", role: "branch", label: "OPENAI_API_KEY", typeLabel: "Credential", entityType: "credential", findings: [], markers: [] };
  const props = { id: "cred", data: { node, vertical: false, onOpenFindings: () => {}, onExpandGroup: () => {} } } as unknown as Parameters<typeof AttackPathGraphNode>[0];
  const { container } = render(<ReactFlowProvider><AttackPathGraphNode {...props} /></ReactFlowProvider>);
  expect(container.querySelector(".react-flow__handle.source")).toHaveClass("react-flow__handle-right");
  expect(container.querySelector(".react-flow__handle.target")).toHaveClass("react-flow__handle-left");
  expect(container.querySelector('.react-flow__handle.source[data-handleid="side"]')).toHaveClass("react-flow__handle-right");
});

it("declares every handle a card renders and every handle a link names, so React Flow never drops a link", async () => {
  const { declaredHandles, pathEdgeHandles } = await import("@/lib/attack-path-graph-handles");
  const node: PathGraphNode = { id: "agent", kind: "entity", role: "path", label: "Copilot", typeLabel: "Agent", entityType: "agent", findings: [], markers: [] };
  const props = { id: "agent", data: { node, vertical: false, onOpenFindings: () => {}, onExpandGroup: () => {} } } as unknown as Parameters<typeof AttackPathGraphNode>[0];
  const { container } = render(<ReactFlowProvider><AttackPathGraphNode {...props} /></ReactFlowProvider>);
  const declared = new Set(declaredHandles({ direction: "LR", nodeWidth: 152, nodeHeight: 136 }).map(handle => `${handle.type}:${handle.id ?? ""}`));
  const rendered = [...container.querySelectorAll(".react-flow__handle")].map(handle => `${handle.classList.contains("source") ? "source" : "target"}:${handle.getAttribute("data-handleid") ?? ""}`);
  expect(new Set(rendered)).toEqual(declared);
  const rows = { direction: "LR", positions: new Map([["a", { x: 0, y: 0 }], ["b", { x: 200, y: 168 }], ["c", { x: 200, y: 0 }], ["d", { x: 0, y: 168 }]]) } as const;
  for (const [source, target] of [["a", "b"], ["b", "c"], ["a", "c"], ["c", "a"], ["d", "a"]] as const) {
    const { sourceHandle, targetHandle } = pathEdgeHandles(rows as never, source, target);
    expect(declared.has(`source:${sourceHandle ?? ""}`), `${source}->${target}`).toBe(true);
    expect(declared.has(`target:${targetHandle ?? ""}`), `${source}->${target}`).toBe(true);
  }
});
