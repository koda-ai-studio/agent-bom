import { expect, it } from "vitest";
import { render } from "@testing-library/react";
import { GraphAttributeBadges } from "@/components/graph-attribute-badges";

it("does not repeat unassessed risk scores as canvas badges", () => {
  const { container } = render(<GraphAttributeBadges data={{ label: "Workload", nodeType: "container", riskScore: 72 }} />);
  expect(container.querySelector("[data-semantic-risk]")).toBeNull();
});
