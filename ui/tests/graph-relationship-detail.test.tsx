import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphRelationshipDetail } from "@/components/graph-relationship-detail";
import type { UnifiedEdge } from "@/lib/graph-schema";

const edge: UnifiedEdge = { id: "edge-a", source: "agent-a", target: "function-a", relationship: "uses", direction: "directed", weight: 1, traversable: false,
  first_seen: "2026-10-12T00:00:00Z", last_seen: "2026-10-12T00:01:00Z", evidence: { basis: "configured_target", source: "workflow" }, activity_id: 0 };
function show(ui: React.ReactElement) {
  const view = render(ui);
  fireEvent.click(screen.getByText("Technical details"));
  return view;
}

describe("relationship inspector", () => {
  it("leads with a plain-language summary and keeps collector ids behind Technical details", () => {
    render(<GraphRelationshipDetail edge={{ ...edge, relationship: "vulnerable_to", evidence: { tier: "static_evidence", source: "bundled_advisory_scanner", evidence_tier: "static_evidence" } }}
      scanId="snapshot-a" sourceLabel="pillow@9.0.0" targetLabel="CVE-2023-4863" onClose={vi.fn()} />);
    const summary = screen.getByLabelText("Relationship summary");
    expect(summary).toHaveTextContent("pillow@9.0.0 is recorded as affected by CVE-2023-4863.");
    expect(summary).toHaveTextContent("Bundled advisory database");
    expect(summary).toHaveTextContent("Static — read from files, manifests or configuration");
    expect(summary).toHaveTextContent("Recorded 2026-10-12 00:01 UTC");
    expect(summary).toHaveTextContent("Whether the vulnerable code is loaded or reachable at runtime.");
    expect(summary).not.toHaveTextContent("bundled_advisory_scanner");
    const technical = screen.getByText("Technical details").closest("details")!;
    expect(technical).not.toHaveAttribute("open");
    expect(technical).toContainElement(screen.getByText("bundled_advisory_scanner"));
    expect(technical).toContainElement(screen.getByLabelText("Relationship evidence and freshness"));
  });

  it.each([
    { evidence: { source: "source-ast" }, title: "Configured delegation" },
    { evidence: {}, title: "Delegation (unverified)" },
    { evidence: { data_source: "runtime-proxy" }, title: "Delegated To" },
  ])("qualifies delegation as $title", ({ evidence, title }) => {
    show(<GraphRelationshipDetail edge={{ ...edge, relationship: "delegated_to", evidence }} scanId="snapshot-a" sourceLabel="Planner" targetLabel="Worker" onClose={vi.fn()} />);
    expect(screen.getByRole("heading", { name: title })).toBeVisible();
  });
  it.each([
    { relationship: "uses", sourceLabel: "Planner", targetLabel: "Invoice function", title: "Uses · configured" },
    { relationship: "vulnerable_to", sourceLabel: "MCP server", targetLabel: "CVE-2025-29927", title: "Has finding" },
  ])("preserves $relationship without inventing an entity type", ({ relationship, sourceLabel, targetLabel, title }) => {
    show(<GraphRelationshipDetail edge={{ ...edge, relationship }} scanId="snapshot-a" sourceLabel={sourceLabel} targetLabel={targetLabel} onClose={vi.fn()} />);
    expect(screen.getByRole("heading", { name: title })).toBeVisible();
    expect(screen.getByText(`${sourceLabel} → ${targetLabel}`)).toBeVisible();
    expect(screen.getByText(/does not establish execution/)).toBeVisible();
  });
  it("shows recorded direction, scope and evidence without promoting execution", () => {
    const close = vi.fn();
    show(<GraphRelationshipDetail edge={edge} scanId="snapshot-a" sourceLabel="Planner" targetLabel="Invoice function" onClose={close} />);
    expect(screen.getByText("Planner → Invoice function")).toBeVisible();
    expect(screen.getByText("snapshot-a")).toBeVisible();
    expect(screen.getByText(/does not establish execution/)).toBeVisible();
    fireEvent.click(screen.getByText("Recorded evidence"));
    expect(screen.getByText(/"basis": "configured_target"/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Close relationship details" }));
    expect(close).toHaveBeenCalledOnce();
  });
  it("shows unavailable timestamps honestly and closes with Escape", () => {
    const close = vi.fn();
    show(<GraphRelationshipDetail edge={{ ...edge, first_seen: "", last_seen: "", direction: "bidirectional" }} scanId="s" sourceLabel="Planner" targetLabel="Worker" onClose={close} />);
    expect(screen.getByText("Planner ↔ Worker")).toBeVisible();
    expect(screen.getByText("Graph first seen").nextElementSibling).toHaveTextContent("Not recorded");
    expect(screen.getByText("Graph last seen").nextElementSibling).toHaveTextContent("Not recorded");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalledOnce();
  });
});
it("moves focus into details and restores the invoking control on close", () => {
  const trigger = document.createElement("button");
  document.body.append(trigger); trigger.focus();
  const view = render(<GraphRelationshipDetail edge={edge} scanId="s" sourceLabel="Planner" targetLabel="Worker" onClose={vi.fn()} />);
  expect(screen.getByRole("button", { name: "Close relationship details" })).toHaveFocus();
  view.unmount();
  expect(trigger).toHaveFocus(); trigger.remove();
});

it.each([
  ["uses", "A recorded use relationship. It does not establish that a tool was called."],
  ["provides_tool", "The source lists the target as an available tool. Availability does not prove invocation."],
  ["depends_on", "The source is linked to a dependency in the collected inventory. This does not establish that vulnerable code runs."],
  ["vulnerable_to", "The source is linked to a security finding. Review its affected asset, evidence, and remediation before choosing a fix."],
])("explains %s without opening raw evidence", (relationship, explanation) => {
  show(<GraphRelationshipDetail edge={{ ...edge, relationship }} scanId="s" sourceLabel="Source" targetLabel="Target" onClose={vi.fn()} />);
  expect(screen.getByText(explanation)).toBeVisible();
  expect(screen.getByText("workflow")).toBeVisible();
  expect(screen.getByText("configured_target")).toBeVisible();
});

it("explains conservative tool impact without claiming a traced exploit", () => {
  show(<GraphRelationshipDetail edge={{ ...edge, relationship: "exploitable_via", evidence: { mapping_method: "server_scope_conservative", package: "example", version: "1.2", source: "scan" } }} scanId="s" sourceLabel="Finding" targetLabel="Tool" onClose={vi.fn()} />);
  expect(screen.getByText(/shares a server with the affected package/)).toBeVisible();
  expect(screen.getByText(/exact package-to-tool call path is not established/)).toBeVisible();
  expect(screen.getByText("example")).toBeVisible();
  expect(screen.getByText("1.2")).toBeVisible();
});

it("does not infer a source receipt from the relationship verb", () => {
  show(<GraphRelationshipDetail edge={{ ...edge, evidence: {} }} scanId="s" sourceLabel="Agent" targetLabel="Server" onClose={vi.fn()} />);
  expect(screen.getByText("Source evidence not recorded for this link.")).toBeVisible();
});

it.each(["future_relationship", "constructor"])("keeps unknown %s relationships neutral", relationship => {
  show(<GraphRelationshipDetail edge={{ ...edge, relationship, evidence: { source: { unexpected: true }, mapping_method: ["not-a-method"] } }} scanId="s" sourceLabel="A" targetLabel="B" onClose={vi.fn()} />);
  expect(screen.getByText(/Review its source evidence before drawing a security conclusion/)).toBeVisible();
  expect(screen.queryByLabelText("Recorded link evidence")).not.toBeInTheDocument();
});

it.each([
  [{ basis: "configured_target" }, "Static / configured"],
  [{ evidence_tier: "static_scan" }, "Static / configured"],
  [{ evidence_basis: "inferred" }, "Inferred"],
  [{ evidence_tier: "modeled_infrastructure" }, "Modeled"],
  [{ evidence_tier: "runtime_observed" }, "Runtime observed"],
  [{ evidence_tier: "runtime_blocked" }, "Runtime blocked"],
  [{ source: "runtime-proxy" }, "Runtime receipt"],
  [{ source: "cloud-audit-trail", observed: true }, "Cloud audit observation"],
  [{ source: "cloud-audit-trail" }, "Not recorded"],
  [{ source: "cloud-inventory" }, "Static / configured"],
  [{ source: "agent_discovery", credential_env_var: "TOKEN" }, "Static / configured"],
  [{ source: "repo-structure-overlay" }, "Static / configured"],
  [{ source: "gateway", runtime_observed_state: "blocked" }, "Runtime blocked"],
  [{ source: "gateway", blocked: true }, "Runtime blocked"],
  [{ source: ["runtime-proxy"] }, "Not recorded"],
  [{ evidence_tier: "future_evidence" }, "Unclassified"],
  [{ source: "source-ast", evidence_tier: "runtime_observed" }, "Mixed recorded evidence"],
  [{ evidence_tier: ["runtime_observed"], observed_at: { time: "invalid" } }, "Not recorded"],
  [{}, "Not recorded"],
])("shows the recorded evidence kind without deriving it from traversal: %j", (evidence, expected) => {
  show(<GraphRelationshipDetail edge={{ ...edge, relationship: "invoked", traversable: true, evidence }} scanId="s" sourceLabel="A" targetLabel="B" onClose={vi.fn()} />);
  expect(screen.getByText("Evidence type").nextElementSibling).toHaveTextContent(expected);
  expect(screen.getByText("Source observed at").nextElementSibling).toHaveTextContent("Not recorded");
  expect(screen.getByText("Graph last seen").nextElementSibling).toHaveTextContent(edge.last_seen);
  expect(screen.getByText(/Traversal eligibility does not establish runtime reachability/)).toBeVisible();
});

it("does not label a misconfiguration as a CVE", () => {
  show(<GraphRelationshipDetail edge={{ ...edge, relationship: "vulnerable_to" }} scanId="s" sourceLabel="Server" targetLabel="Missing authentication" onClose={vi.fn()} />);
  expect(screen.getByRole("heading", { name: "Has finding" })).toBeVisible();
});

it("keeps source observation, receipt timestamp and graph freshness distinct", () => {
  const observed = "2026-09-01T01:00:00Z", event = "2026-09-02T02:00:00Z";
  show(<GraphRelationshipDetail edge={{ ...edge, evidence: { observed_at: observed, timestamp: event, evidence_tier: "runtime_blocked" } }} scanId="s" sourceLabel="A" targetLabel="B" onClose={vi.fn()} />);
  expect(screen.getByText("Source observed at").nextElementSibling).toHaveTextContent(observed);
  expect(screen.getByText("Receipt timestamp").nextElementSibling).toHaveTextContent(event);
  expect(screen.getByText("Graph last seen").nextElementSibling).toHaveTextContent(edge.last_seen);
  expect(screen.getByText("Evidence type").nextElementSibling).toHaveTextContent("Runtime blocked");
});

it("labels a scan-recorded link without a per-edge receipt by its snapshot origin", () => {
  show(<GraphRelationshipDetail edge={{ ...edge, evidence: {}, source_scan_id: "scan-1" }} scanId="s" sourceLabel="Agent" targetLabel="Server" onClose={vi.fn()} />);
  expect(screen.getByText("Evidence type").nextElementSibling).toHaveTextContent("Scan inventory · no per-edge receipt");
});
