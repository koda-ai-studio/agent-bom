import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphScopeFindings } from "@/components/graph-scope-findings";
import { api } from "@/lib/api";

vi.mock("@/lib/api", () => ({ api: { getGraphScopeFindings: vi.fn() } }));

describe("scope finding disclosure", () => {
  it("opens original evidence ids and pins continuation to both revisions", async () => {
    vi.mocked(api.getGraphScopeFindings).mockResolvedValue({ scan_id: "scan", node_id: "agent", snapshot_generation: "generation", finding_revision: "revision",
      total: 21, offset: 0, limit: 20, findings: [{ issue_key: "issue", label: "Recorded finding", severity: "high", node_ids: ["original-finding"] }] });
    const inspect = vi.fn();
    render(<GraphScopeFindings scanId="scan" nodeId="agent" label="Agent" expected={21} excludeNodeIds={["server"]} onClose={vi.fn()} onInspect={inspect} />);
    fireEvent.click(await screen.findByRole("button", { name: "Inspect evidence" }));
    expect(inspect).toHaveBeenCalledWith("original-finding", "Recorded finding");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(api.getGraphScopeFindings).toHaveBeenCalledWith("scan", "agent", 20, "generation", "revision", ["server"]));
  });
  it("does not render a failed disclosure as zero findings", async () => {
    vi.mocked(api.getGraphScopeFindings).mockRejectedValue(new Error("unavailable"));
    render(<GraphScopeFindings scanId="scan" nodeId="agent" label="Agent" expected={1} onClose={vi.fn()} onInspect={vi.fn()} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("This is not a clean result");
    expect(screen.queryByText("0 open issues")).not.toBeInTheDocument();
  });
});
