import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AIAdviceBadge, AIAdviceSection, AIStatusNotice, aiVerdictLabel, type AIAssessment } from "@/components/ai-advice";
import { AIPathExplainPanel } from "@/components/ai-path-explain-panel";
import { collectUnifiedFindings } from "@/lib/findings-adapter";

const explainGraph = vi.fn();
vi.mock("@/lib/api-ai-advice", () => ({
  explainGraphSelection: (...args: unknown[]) => explainGraph(...args),
}));

afterEach(() => {
  cleanup();
  explainGraph.mockReset();
});

const assessment: AIAssessment = {
  finding_id: "f1",
  verdict: "likely_false_positive",
  confidence: "high",
  rationale: "Installed 2.0.0 is at the fix.",
  advisory: true,
  guard_applied: false,
  protected_reasons: [],
  provenance: { model: "ollama/llama3.2", model_digest: "sha256:abcdef1234567890", prompt_version: "ai-triage.v3", dataset_version: "ai-triage-dataset.v1", generated_at: "2026-11-05T12:00:00+00:00" },
};

describe("AI advice", () => {
  it("names verdicts in plain words", () => {
    expect(aiVerdictLabel("likely_false_positive")).toBe("Likely false positive");
    expect(aiVerdictLabel("confirmed")).toBe("Confirmed");
    expect(aiVerdictLabel("needs_review")).toBe("Needs review");
    expect(aiVerdictLabel("somethingelse")).toBe("Needs review");
  });

  it("labels the drawer section as AI advice and shows verdict, confidence, reason, model and date", () => {
    render(<AIAdviceSection assessment={assessment} />);
    const section = screen.getByRole("region", { name: "AI advice" });
    expect(section.textContent).toContain("Likely false positive");
    expect(section.textContent).toContain("High confidence");
    expect(section.textContent).toContain("Installed 2.0.0 is at the fix.");
    expect(section.textContent).toContain("ollama/llama3.2");
    expect(section.textContent).toContain("2026-11-05");
    expect(section.textContent).toContain("does not change scanner severity");
  });

  it("explains a discarded dismissal", () => {
    render(<AIAdviceSection assessment={{ ...assessment, verdict: "confirmed", guard_applied: true, protected_reasons: ["kev"], rationale: "Scanner evidence stands." }} />);
    expect(screen.getByRole("region", { name: "AI advice" }).textContent).toContain("known-exploited");
  });

  it("renders hostile model text as text, never as markup or a link", () => {
    const hostile = '<img src=x onerror="alert(1)"><a href="javascript:alert(1)">click</a> [link](http://evil.example)';
    const { container } = render(<AIAdviceSection assessment={{ ...assessment, rationale: hostile }} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain(hostile);
  });

  it("shows nothing in the drawer when a finding has no assessment", () => {
    const { container } = render(<AIAdviceSection assessment={null} />);
    expect(container.textContent).toBe("");
  });

  it("keeps the row badge apart from severity wording", () => {
    render(<AIAdviceBadge assessment={assessment} />);
    const badge = screen.getByLabelText(/AI advice: Likely false positive/);
    expect(badge.textContent).toContain("AI");
    expect(badge.textContent?.toLowerCase()).not.toContain("critical");
  });

  it("states clearly when AI is off, failed, or on", () => {
    const { rerender } = render(<AIStatusNotice status={{ state: "off", reason: "AI advice is off: the operator has not set AGENT_BOM_AI_CONTROL_PLANE_ENABLED.", last_run: null, advisory_only: true, schema_version: "v1" }} />);
    expect(screen.getByRole("status").textContent).toContain("AI advice is off");
    rerender(<AIStatusNotice status={{ state: "degraded", reason: "", advisory_only: true, schema_version: "v1", last_run: { scan_id: "s", created_at: "2026-11-05T00:00:00+00:00", status: "failed", reason: "deadline" } }} />);
    expect(screen.getByRole("status").textContent).toContain("last AI run failed");
    expect(screen.getByRole("status").textContent).toContain("Scanner findings are unaffected");
    rerender(<AIStatusNotice status={{ state: "on", reason: "", advisory_only: true, schema_version: "v1", last_run: { scan_id: "s", created_at: "2026-11-05T00:00:00+00:00", status: "ok", model: "ollama/llama3.2", triage_scope: { findings_total: 300, findings_offered: 100, skipped: { below_risk_cutoff: 200 } } } }} />);
    expect(screen.getByRole("status").textContent).toContain("100 of 300");
  });
});

const explanation = {
  schema_version: "ai.graph-explanation.v1",
  advisory: true,
  label: "AI advice",
  status: "ok",
  claims: [
    {
      text: "The agent uses this server. <script>alert(1)</script>",
      citations: [
        { ref: "E1", kind: "edge", id: "edge:abc", label: "agent uses server", traversable: true },
        { ref: "N1", kind: "node", id: "agent:a", label: "agent a", traversable: null },
      ],
    },
  ],
  rejected_claims: { uncited: 2 },
  evidence_limits: ["The edge from a to b is not traversable: it records a relationship, not a route."],
  provenance: { model: "ollama/llama3.2", provider: "ollama", model_digest: "sha256:abc", prompt_version: "ai-graph-explain.v1", generated_at: "2026-11-05T12:00:00+00:00" },
};

describe("finding rows", () => {
  it("keep the stored advice through the adapter without touching severity", () => {
    const [row] = collectUnifiedFindings([{ id: "f1", severity: "critical", ai_assessment: assessment, asset: { name: "lib", asset_type: "package" }, finding_type: "CVE", title: "x" } as never]);
    expect(row?.ai_assessment?.verdict).toBe("likely_false_positive");
    expect(row?.severity).toBe("critical");
  });

  it("carry null when no advice exists", () => {
    const [row] = collectUnifiedFindings([{ id: "f2", severity: "low", asset: { name: "lib", asset_type: "package" }, finding_type: "CVE", title: "x" } as never]);
    expect(row?.ai_assessment).toBeNull();
  });
});

describe("Explain this path", () => {
  it("calls the model only on demand and shows citations, limits and the label", async () => {
    explainGraph.mockResolvedValue(explanation);
    const { container } = render(<AIPathExplainPanel nodeIds={["agent:a", "server:s"]} scanId="scan-1" />);
    expect(explainGraph).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Explain this path" }));
    await waitFor(() => expect(screen.getByText(/The agent uses this server/)).toBeTruthy());
    expect(explainGraph).toHaveBeenCalledTimes(1);
    expect(explainGraph).toHaveBeenCalledWith({ nodeIds: ["agent:a", "server:s"], ordered: true, scanId: "scan-1" });
    const panel = screen.getByRole("region", { name: "Path explanation, AI advice" });
    expect(panel.textContent).toContain("agent uses server");
    expect(panel.textContent).toContain("agent:a");
    expect(panel.textContent).toContain("not traversable");
    expect(panel.textContent).toContain("2 claims were removed");
    expect(panel.textContent).toContain("ollama/llama3.2");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
  });

  it("says why it cannot explain when AI is off", async () => {
    explainGraph.mockRejectedValue({ status: 409, message: "AI advice is off: the operator has not set AGENT_BOM_AI_CONTROL_PLANE_ENABLED." });
    render(<AIPathExplainPanel nodeIds={["a"]} />);
    fireEvent.click(screen.getByRole("button", { name: "Explain this path" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("AI advice is off"));
  });

  it("reports when every claim was removed rather than showing an empty success", async () => {
    explainGraph.mockResolvedValue({ ...explanation, status: "rejected", claims: [] });
    render(<AIPathExplainPanel nodeIds={["a"]} />);
    fireEvent.click(screen.getByRole("button", { name: "Explain this path" }));
    await waitFor(() => expect(screen.getByRole("region", { name: "Path explanation, AI advice" }).textContent).toContain("No claim could be tied to recorded graph evidence"));
  });
});
