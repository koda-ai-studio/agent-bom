import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { GraphScenarioUnconnected } from "@/components/graph-scenario-unconnected";

it("keeps disconnected proposal evidence selectable outside the graph", () => {
  const node = { id: "credential", position: { x: 0, y: 0 }, data: { label: "DEMO_CRED_REF", nodeType: "credential" as const } };
  const onSelect = vi.fn();
  render(<GraphScenarioUnconnected nodes={[node]} notes={new Map([[node.id, "Connection removed in proposal"]])} selectedId={node.id} onSelect={onSelect} />);
  const panel = screen.getByRole("region", { name: "Unconnected proposal items" });
  expect(panel).toHaveTextContent("Unconnected proposal items · 1");
  const button = screen.getByRole("button", { name: /DEMO_CRED_REF/ });
  expect(button).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(button);
  expect(onSelect).toHaveBeenCalledWith(node);
});

it("does not show a panel when every displayed item is connected", () => {
  render(<GraphScenarioUnconnected nodes={[]} notes={new Map()} selectedId={null} onSelect={vi.fn()} />);
  expect(screen.queryByRole("region", { name: "Unconnected proposal items" })).not.toBeInTheDocument();
});
