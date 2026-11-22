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
