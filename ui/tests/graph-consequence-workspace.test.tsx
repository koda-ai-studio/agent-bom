import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphConsequenceResults } from "@/components/graph-consequence-results";

const item = { id: "read", category: "read_data", status: "supported", action: "storage.objects.get", resource: "projects/acme/buckets/reports", target_node_id: "bucket:r", node_ids: ["agent:a", "principal:p", "bucket:r"], node_labels: ["Research assistant", "Report reader", "Reports"], node_types: ["agent", "service_account", "data_store"], edge_ids: ["session:a", "grant:r"], session_ids: ["session:a"], binding_ids: ["grant:r"], reason_codes: [], observation: "not_recorded", evidence_refs: ["receipt:r"] };
const result = { scan_id: "s", snapshot_generation: "rev", assessed_at: "2026-10-11T00:00:00Z", request: { mode: "assumed_compromise" }, consequences: [item, {...item, id: "deny", category: "delete_resource", action: "storage.objects.delete", status: "blocked", deny_binding_ids: ["deny:d"], reason_codes: ["recorded_denial"]}], frontier: [], prerequisites: {reason_codes: []}, counts: {supported: 1, conditional: 0, blocked: 1, unknown: 0}, truncated: false };
it("focuses the selected consequence in a wide investigation with its actual identity path", () => {
  render(<GraphConsequenceResults result={result as never} />);
  expect(screen.getByRole("dialog", {name: "Consequence investigation"})).toBeVisible();
  expect(screen.getByRole("heading", {name: "Read data from Reports"})).toBeVisible();
  const path = screen.getByRole("list", {name: "Selected consequence path"});
  expect(path).toHaveTextContent("Research assistant");
  expect(path).toHaveTextContent("Report reader");
  expect(path).toHaveTextContent("Reports");
  fireEvent.click(screen.getByRole("button", {name: /Delete a resource.*Reports/}));
  expect(screen.getByRole("heading", {name: "Delete Reports"})).toBeVisible();
  expect(screen.getByText("Recorded denial stops this action")).toBeVisible();
  expect(screen.getByText(/rev/)).toBeTruthy();
});

it("distinguishes a session scope blocker from a provider denial", () => {
  const scoped = { ...item, status: "blocked", reason_codes: ["outside_session_scope"] };
  render(<GraphConsequenceResults result={{ ...result, consequences: [scoped] } as never} />);
  expect(screen.getByText("Recorded session scope excludes this action")).toBeVisible();
  expect(screen.queryByText("Recorded denial stops this action")).not.toBeInTheDocument();
});
