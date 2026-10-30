import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphConsequencePanel } from "@/components/graph-consequence-panel";
import { api } from "@/lib/api";
import * as stories from "@/lib/api-exploit-story";
import { exploitStoryFixture, STORY_ADVISORY, STORY_PACKAGE } from "../e2e/exploit-story-fixture";

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

function impactStory() {
  return { ...exploitStoryFixture("scan-one"), tenant_id: "tenant-a", snapshot_generation: "revision-one" } as stories.ExploitStoryResponse;
}

it("opens CVE workflow and impact from the selected occurrence without assuming exploitation", async () => {
  const call = vi.spyOn(stories, "getExploitStory").mockResolvedValue(impactStory());
  const assess = vi.spyOn(api, "assessConsequences");
  render(<GraphConsequencePanel nodeId={`vuln:${STORY_ADVISORY}`} scanId="scan-one" snapshotGeneration="revision-one" findingRoot affectedNodeIds={[STORY_PACKAGE]} />);
  expect(screen.getByRole("heading", { name: "How could this CVE affect us?" })).toBeVisible();
  expect(call).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Open CVE impact workspace" }));
  const workspace = await screen.findByRole("dialog", { name: "CVE workflow and impact" });
  const flow = await within(workspace).findByRole("list", { name: "Component to workflow to potential impact" });
  expect(within(flow).getByText("orchestrator-lib@1.0.0")).toBeVisible();
  expect(within(flow).getByText("orchestrator-server")).toBeVisible();
  expect(within(workspace).getByText("Local exploitability: not established")).toBeVisible();
  expect(within(workspace).getByRole("heading", { name: "Advisory conditions" })).toBeVisible();
  expect(within(workspace).getByText(/Sharing an environment does not establish an access path/)).toBeVisible();
  expect(call.mock.calls[0]![0]).toMatchObject({ node: `vuln:${STORY_ADVISORY}`, packageNode: STORY_PACKAGE, scanId: "scan-one" });
  expect(assess).not.toHaveBeenCalled();
});

it("requires a linked occurrence before reading a multi-component CVE", async () => {
  const call = vi.spyOn(stories, "getExploitStory").mockResolvedValue(impactStory());
  render(<GraphConsequencePanel nodeId={`vuln:${STORY_ADVISORY}`} scanId="scan-one" findingRoot affectedNodeIds={[STORY_PACKAGE, "package:other"]} />);
  fireEvent.click(screen.getByRole("button", { name: "Open CVE impact workspace" }));
  const workspace = screen.getByRole("dialog", { name: "CVE workflow and impact" });
  expect(call).not.toHaveBeenCalled();
  fireEvent.change(within(workspace).getByLabelText("Affected component"), { target: { value: STORY_PACKAGE } });
  const flow = await within(workspace).findByRole("list", { name: "Component to workflow to potential impact" });
  expect(within(flow).getByText("orchestrator-lib@1.0.0")).toBeVisible();
  expect(call).toHaveBeenCalledTimes(1);
});

it.each(["snapshot", "tenant", "finding", "component"])("withholds an impact story from the wrong %s", async (mismatch) => {
  const value = impactStory();
  if (mismatch === "snapshot") value.snapshot_generation = "stale-revision";
  if (mismatch === "tenant") value.tenant_id = "other-tenant";
  if (mismatch === "finding") value.vulnerability_node_id = "vuln:other";
  if (mismatch === "component") value.package = { ...value.package!, id: "package:other" };
  vi.spyOn(stories, "getExploitStory").mockResolvedValue(value);
  render(<GraphConsequencePanel nodeId={`vuln:${STORY_ADVISORY}`} scanId="scan-one" snapshotGeneration="revision-one" findingRoot affectedNodeIds={[STORY_PACKAGE]} />);
  fireEvent.click(screen.getByRole("button", { name: "Open CVE impact workspace" }));
  const workspace = screen.getByRole("dialog", { name: "CVE workflow and impact" });
  await within(workspace).findByRole("alert");
  expect(within(workspace).queryByText("orchestrator-lib@1.0.0")).not.toBeInTheDocument();
});

it("keeps partial discovery and absent connections distinct from a clean verdict", async () => {
  const value = impactStory();
  value.at_risk.groups = [];
  value.at_risk.completeness.complete = false;
  vi.spyOn(stories, "getExploitStory").mockResolvedValue(value);
  render(<GraphConsequencePanel nodeId={`vuln:${STORY_ADVISORY}`} scanId="scan-one" findingRoot affectedNodeIds={[STORY_PACKAGE]} />);
  fireEvent.click(screen.getByRole("button", { name: "Open CVE impact workspace" }));
  const workspace = screen.getByRole("dialog", { name: "CVE workflow and impact" });
  await within(workspace).findByText(/Partial graph evidence/);
  expect(within(workspace).getByText(/No connected targets returned/)).toHaveTextContent("not a clean verdict");
});

it("cancels the CVE read when its workspace closes and does not show a late result", async () => {
  let finish!: (value: stories.ExploitStoryResponse) => void;
  const call = vi.spyOn(stories, "getExploitStory").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<GraphConsequencePanel nodeId={`vuln:${STORY_ADVISORY}`} scanId="scan-one" findingRoot affectedNodeIds={[STORY_PACKAGE]} />);
  fireEvent.click(screen.getByRole("button", { name: "Open CVE impact workspace" }));
  const workspace = screen.getByRole("dialog", { name: "CVE workflow and impact" });
  fireEvent.click(within(workspace).getByRole("button", { name: "Back to graph" }));
  expect(call.mock.calls[0]![1]?.signal?.aborted).toBe(true);
  finish(impactStory());
  await waitFor(() => expect(screen.queryByText("Local exploitability: not established")).not.toBeInTheDocument());
});
