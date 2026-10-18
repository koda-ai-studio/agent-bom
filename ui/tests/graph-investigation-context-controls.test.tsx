import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { GraphInvestigationContextControls } from "@/components/graph-investigation-context-controls";

it("makes excluded context and its cross-group links explicit", () => {
  const onSelect = vi.fn();
  render(<GraphInvestigationContextControls groups={[
    { id: "dependency", label: "Dependency evidence", nodeIds: ["package"] },
    { id: "workload", label: "Workload and access context", nodeIds: ["agent"] },
  ]} selected="dependency" visibleNodes={5} loadedNodes={10} crossContextEdges={1} onSelect={onSelect} />);
  expect(screen.getByLabelText("Investigation context")).toHaveTextContent("5 of 10 loaded nodes shown.");
  expect(screen.getByText(/1 relationship crosses groups/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Dependency evidence" })).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: "All relationships" }));
  expect(onSelect).toHaveBeenCalledWith("all");
});
