import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { FindingDrawer } from "@/components/finding-drawer";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const source = "sbom:/private/tmp/reference/model.cdx.json";
const base: EnrichedVuln = {
  id: "CVE-2020-14343", severity: "high", packages: ["pyyaml"], agents: [source],
  affected_servers: [source], sources: [], exposed_credentials: [], reachable_tools: [],
  references: [], advisory_sources: [], remediation_items: [],
};

it("presents SBOM artifacts as sources across overview and evidence without losing their paths", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={base} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("SBOM evidence; workload not identified")).toBeVisible();
  expect(screen.getByText("SBOM source: model.cdx.json")).toBeVisible();
  expect(screen.queryByText(/1 agent|1 MCP server/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("SBOM sources")).toBeVisible();
  expect(screen.getByText(source)).toBeVisible();
  expect(screen.queryByText("Agents")).not.toBeInTheDocument();
  expect(screen.queryByText("MCP servers")).not.toBeInTheDocument();
  expect(screen.queryByText(/1 agent surface/)).not.toBeInTheDocument();
  expect(base.agents).toEqual([source]);
  expect(base.affected_servers).toEqual([source]);
});

it("keeps real agents and servers alongside separately labeled SBOM evidence", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, agents: [source, "cursor"], affected_servers: [source, "api-mcp"] }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("1 agent · 1 MCP server")).toBeVisible();
  expect(screen.queryByText(/workload not identified/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("Agents")).toBeVisible();
  expect(screen.getByText("MCP servers")).toBeVisible();
  expect(screen.getByText(source)).toBeVisible();
  expect(screen.getByText(/1 agent surface/)).toBeVisible();
});


it("renders structured CWEs without mining summary prose", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, cwe_ids: ["CWE-79", "CWE-79", "CWE-89"], summary: "An unrelated CWE-999 label in advisory prose" }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("Weaknesses")).toBeVisible();
  expect(screen.getAllByText("CWE-79")).toHaveLength(1);
  expect(screen.getByText("CWE-89")).toBeVisible();
  expect(screen.queryByText("CWE-999", { exact: true })).not.toBeInTheDocument();
});

it("keeps unreconfirmed status and collection attempt separate from original evidence", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, observation_status: "unreconfirmed", last_observed: "2026-08-01T00:00:00Z", scan_id: "baseline-scan", reconfirmation: { scan_id: "partial-candidate", attempted_at: "2026-09-01T00:00:00Z", reason_codes: ["scope_permission_denied"] } }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByRole("note", { name: "Unreconfirmed collection evidence" })).toHaveTextContent("Current presence unconfirmed");
  expect(screen.getByText("Collection permission denied")).toBeVisible();
  expect(screen.getByText("partial-candidate")).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByRole("note", { name: "Unreconfirmed collection evidence" })).toBeVisible();
  expect(screen.getByText("baseline-scan")).toBeVisible();
  expect(screen.getByText("Last observed:")).toBeVisible();
});

it("qualifies a group with an observed representative and an unreconfirmed occurrence", () => {
  render(<FindingDrawer vuln={{ ...base, observation_status: "observed", unreconfirmed_occurrence_count: 1, occurrence_count: 2 }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByRole("note", { name: "Unreconfirmed collection evidence" })).toHaveTextContent("1 occurrence retains earlier evidence");
  expect(screen.queryByText(/Latest attempt:/)).not.toBeInTheDocument();
});


it.each(["observed", "blocked"] as const)("qualifies %s runtime activity without claiming vulnerable-code execution", async (state) => {
  render(<FindingDrawer vuln={{ ...base, runtime_evidence: { state, observed_count: state === "observed" ? 1 : 0, blocked_count: state === "blocked" ? 1 : 0 } }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  await userEvent.setup().click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText(`Related runtime activity: ${state}`)).toBeVisible();
  expect(screen.getByText("Matched agent or tool activity; this does not prove execution of the vulnerable code or exploitation.")).toBeVisible();
  expect(screen.queryByText(`Runtime ${state}`)).not.toBeInTheDocument();
});

it("does not imply runtime observation for static evidence", async () => {
  render(<FindingDrawer vuln={{ ...base, runtime_evidence: { state: "static" } }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  await userEvent.setup().click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.queryByText(/Related runtime activity:/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Matched agent or tool activity/)).not.toBeInTheDocument();
});

it.each(["infra/main.tf", undefined, "/private/host/infra/main.tf", "../outside/main.tf"])("shows only explicit repository-relative IaC context: %s", async (repository_relative_path) => {
  render(<FindingDrawer vuln={{ ...base, finding_class: "misconfiguration", repository_relative_path } as EnrichedVuln} lens="trust" triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("Repository location")).toBeVisible();
  expect(screen.getByText(repository_relative_path === "infra/main.tf" ? "infra/main.tf" : "Unknown — no verified repository-relative location supplied")).toBeVisible();
  if (repository_relative_path?.startsWith("/") || repository_relative_path?.startsWith("..")) expect(screen.queryByText(repository_relative_path)).not.toBeInTheDocument();
});

it("shows the finding's own remediation guidance as the next action", () => {
  const guidance = "Broker credentials through a short-lived token issuer instead of exposing them to the agent.";
  render(<FindingDrawer vuln={{ ...base, remediation_items: [{ package: "agent", ecosystem: "agent", current_version: "", fixed_version: null, action: "review", command: null, verify_command: null, references: [], risk_narrative: guidance }] }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText(guidance)).toBeVisible();
  expect(screen.queryByText("Review the evidence and determine the appropriate fix.")).not.toBeInTheDocument();
});

it("keeps the generic next action only when no remediation is recorded", () => {
  render(<FindingDrawer vuln={base} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("Review the evidence and determine the appropriate fix.")).toBeVisible();
});

it("keeps the finding snapshot on its remediation link", () => {
  render(<FindingDrawer vuln={{ ...base, scan_id: "scan-original", fixed_version: "6.0" }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByRole("link", { name: "Review remediation" })).toHaveAttribute("href", "/remediation?q=CVE-2020-14343&scan=scan-original");
});

it("keeps a review-only advisory match unknown despite a legacy green score", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, match_confidence_tier: "unverified_range", effective_reach_band: "green", effective_reach_score: 5, runtime_evidence: { state: "observed", observed_count: 1 } }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("Reachability unknown")).toBeVisible();
  expect(screen.getByText("Related runtime activity: observed")).toBeVisible();
  expect(screen.queryByText(/Reach green|Reported reachability is green/i)).not.toBeInTheDocument();
  expect(screen.getByText(/advisory match needs verification/i)).toBeVisible();
});
