import { expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import { canvasName } from "@/components/graph-compact-node";

it("keeps names up to 28 characters whole and shortens image digests", () => {
  expect(canvasName("Reference Evidence Workload")).toBe("Reference Evidence Workload");
  expect(canvasName("reference-evidence-api@sha256:0123456789abcdeff477d58a")).toBe("reference-evidence-api @ f477d58a");
  const long = canvasName("an extremely long deployment name with many words");
  expect(long.length).toBeLessThanOrEqual(28);
  expect(long).toContain("…");
});

it("draws one circle, a two-line name and one type line with no canvas chips", () => {
  const Renderer = lineageNodeTypes.dataStoreNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Customer data", nodeType: "dataStore", semanticLayout: true,
    attributes: { admin_equivalent: true, data_classification: "confidential", risk_context: { internet_exposed: true } }, isKev: true }} /></ReactFlowProvider>);
  expect(container.querySelector("[data-compact-node]")).not.toBeNull();
  expect(container.querySelector("[data-semantic-name]")).toHaveClass("line-clamp-2");
  expect(container.querySelector("[data-semantic-badges]")).toBeNull();
  expect(container.querySelector('[data-compact-marker="kev"]')).not.toBeNull();
  expect(container.querySelector('[data-compact-marker="internet"]')).not.toBeNull();
});
