import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphConsequencePanel } from "@/components/graph-consequence-panel";
import { api } from "@/lib/api";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: { tenant_id: "tenant-a" } }) }));
afterEach(() => vi.restoreAllMocks());
function result() {
  return { scan_id: "scan-one", snapshot_generation: "revision-one", consequences: [], frontier: [],
    prerequisites: { status: "unknown", reason_codes: ["local_exploitability_not_collected"] },
    counts: { supported: 0, conditional: 0, blocked: 0, unknown: 0, lower_bound: false }, truncated: false };
}
it("requires explicit control and keeps missing evidence visible", async () => {
  const call = vi.spyOn(api, "assessConsequences").mockResolvedValue(result() as never);
  render(<GraphConsequencePanel nodeId="agent:one" scanId="scan-one" snapshotGeneration="revision-one" />);
  fireEvent.click(screen.getByText("Investigate consequences · experimental"));
  expect(call).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Trace consequences" })).toBeDisabled();
  fireEvent.click(screen.getByLabelText("Assume control of this agent or principal"));
  fireEvent.click(screen.getByRole("button", { name: "Trace consequences" }));
  const investigation = await screen.findByRole("dialog", { name: "Consequence investigation" });
  expect(within(investigation).getByText(/No qualified action consequences/)).toBeVisible();
  expect(within(investigation).getByText(/Estate coverage is unknown/)).toBeVisible();
  expect(call.mock.calls[0]![0]).toMatchObject({ mode: "assumed_compromise", assume_control: true, snapshot_generation: "revision-one" });
});
it("selects only linked occurrences and never assumes exploitation", async () => {
  const call = vi.spyOn(api, "assessConsequences").mockResolvedValue(result() as never);
  render(<GraphConsequencePanel nodeId="vuln:one" scanId="scan-one" findingRoot affectedNodeIds={["package:one"]} />);
  fireEvent.click(screen.getByText("Investigate consequences · experimental"));
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Trace consequences" })).toBeDisabled();
  fireEvent.change(screen.getByRole("combobox"), { target: { value: "package:one" } });
  fireEvent.click(screen.getByRole("button", { name: "Trace consequences" }));
  await screen.findByText(/Prerequisites: local exploitability not collected/);
  expect(call.mock.calls[0]![0]).toMatchObject({ mode: "vulnerability", assume_control: false, affected_node_id: "package:one" });
});
it("does not overwrite the selected revision with an earlier response", async () => {
  let finish!: (value: never) => void;
  vi.spyOn(api, "assessConsequences").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const { rerender } = render(<GraphConsequencePanel nodeId="agent:one" scanId="scan-one" snapshotGeneration="old" />);
  fireEvent.click(screen.getByText("Investigate consequences · experimental"));
  fireEvent.click(screen.getByLabelText("Assume control of this agent or principal"));
  fireEvent.click(screen.getByRole("button", { name: "Trace consequences" }));
  expect(screen.getByRole("checkbox")).toBeDisabled();
  rerender(<GraphConsequencePanel nodeId="agent:one" scanId="scan-one" snapshotGeneration="new" />);
  finish(result() as never);
  await waitFor(() => expect(screen.queryByText(/No qualified action/)).not.toBeInTheDocument());
  expect(screen.getByRole("checkbox")).not.toBeChecked();
});
it("renders a safe error without inventing an empty result", async () => {
  vi.spyOn(api, "assessConsequences").mockRejectedValue(new Error("private database secret"));
  render(<GraphConsequencePanel nodeId="agent:one" scanId="scan-one" />);
  fireEvent.click(screen.getByText("Investigate consequences · experimental"));
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Trace consequences" }));
  await screen.findByRole("alert");
  expect(screen.queryByText(/private database secret/)).not.toBeInTheDocument();
  expect(screen.queryByText(/No qualified action/)).not.toBeInTheDocument();
});
