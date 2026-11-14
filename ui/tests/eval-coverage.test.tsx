import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FindingDrawer } from "@/components/finding-drawer";
import { collectUnifiedFindings } from "@/lib/findings-adapter";
import { evalResultSummary, parseEvalCoverageEvidence } from "@/lib/eval-coverage";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const evidence = {
  rule_id: "eval-coverage/safety-gap",
  risk_signals: { write_exec_tools: ["run_shell", "write_file"], credentials: ["OPS_DB_PASSWORD"], data_access: [] },
  searched: { scope: "ops-service", files_examined: 3, statement: "no safety eval found in the scanned project files" },
  linked_evals: [
    {
      harness: "promptfoo",
      name: "Ops quality",
      file_path: "promptfooconfig.yaml",
      purpose: "quality",
      results: [{ source: "promptfoo output file", source_file: "out.json", recorded_at: "2026-09-01T00:00:00Z", passed: 9, failed: 1, errors: 0, pass_rate: 0.9 }],
    },
  ],
  model_level_safety_evals: [],
  unlinked_safety_evals: [{ harness: "deepeval", name: "toxicity", file_path: "evals/tox.py", purpose: "safety", results: [] }],
};

describe("eval coverage evidence", () => {
  it("parses only coverage-gap findings and keeps unknown purposes unknown", () => {
    expect(parseEvalCoverageEvidence("CVE", evidence)).toBeNull();
    const parsed = parseEvalCoverageEvidence("EVAL_COVERAGE_GAP", { ...evidence, linked_evals: [{ purpose: "made-up", results: "bad" }] });
    expect(parsed?.linked[0]?.purpose).toBe("unknown");
    expect(parsed?.linked[0]?.results).toEqual([]);
    expect(parsed?.riskSignals.writeExecTools).toEqual(["run_shell", "write_file"]);
  });

  it("summarises results honestly when nothing was recorded", () => {
    expect(evalResultSummary({ source: "s", source_file: "f", recorded_at: "", passed: 0, failed: 0, errors: 0, pass_rate: null })).toBe("No test outcomes recorded");
    expect(evalResultSummary({ source: "s", source_file: "f", recorded_at: "", passed: 46, failed: 4, errors: 0, pass_rate: 0.92 })).toBe("46 of 50 passed (92%)");
  });

  it("carries the parsed evidence through the findings adapter", () => {
    const [row] = collectUnifiedFindings([
      {
        id: "f-1",
        finding_type: "EVAL_COVERAGE_GAP",
        source: "EVAL_SCAN",
        severity: "medium",
        title: "Agent 'ops_agent' has high-risk capabilities and no linked safety eval",
        asset: { name: "ops_agent", asset_type: "agent" },
        evidence,
      },
    ] as never);
    expect(row?.eval_coverage?.searched.scope).toBe("ops-service");
  });

  it("shows what was searched, the risk signals and labelled results in the finding drawer", async () => {
    const vuln: EnrichedVuln = {
      id: "f-1", severity: "medium", packages: [], agents: ["ops_agent"], affected_servers: [], sources: ["EVAL_SCAN"],
      exposed_credentials: [], reachable_tools: [], references: [], advisory_sources: [], remediation_items: [],
      finding_type: "EVAL_COVERAGE_GAP", eval_coverage: parseEvalCoverageEvidence("EVAL_COVERAGE_GAP", evidence) ?? undefined,
    };
    const user = userEvent.setup();
    render(<FindingDrawer vuln={vuln} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
    await user.click(screen.getByRole("tab", { name: "Evidence" }));
    const panel = screen.getByTestId("eval-coverage-evidence");
    expect(within(panel).getByText(/no safety eval found in the scanned project files/)).toBeVisible();
    expect(within(panel).getByText("run_shell")).toBeVisible();
    expect(within(panel).getByText("OPS_DB_PASSWORD")).toBeVisible();
    expect(within(panel).getByText(/9 of 10 passed \(90%\)/)).toBeVisible();
    expect(within(panel).getByText(/recorded 2026-09-01T00:00:00Z/)).toBeVisible();
    expect(within(panel).getByText("Safety evals that could not be linked to an agent")).toBeVisible();
    expect(within(panel).queryByText(/never/i)).not.toBeInTheDocument();
  });
});
