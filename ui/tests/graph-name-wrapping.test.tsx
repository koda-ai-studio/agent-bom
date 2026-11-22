import { expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";

it("reserves up to four visible name lines before clamping a semantic node, never a one-line truncation", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Reference Evidence Workload", nodeType: "container", semanticLayout: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-semantic-name]")).toHaveClass("line-clamp-4");
  expect(container.querySelector("[data-semantic-name]")).not.toHaveClass("truncate");
});
