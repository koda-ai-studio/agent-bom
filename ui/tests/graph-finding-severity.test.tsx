import { expect, it } from "vitest";
import { render } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { lineageNodeTypes } from "@/components/lineage-nodes";
import counts from "./fixtures/product-proof-rollup.json";

it("colours the counted medium issue independently of critical asset risk", () => {
  const Renderer = lineageNodeTypes.agentNode;
  const {container} = render(<ReactFlowProvider><Renderer data={{label: "Developer Copilot", nodeType: "agent", semanticLayout: true,
    severity: "critical", findingAggregate: counts.node_aggregates["agent:developer-copilot"].aggregate, onExploreFindings: () => {}}} /></ReactFlowProvider>);
  expect(container.querySelector("[data-finding-disclosure]")).toHaveAttribute("data-finding-count-severity", "medium");
});
