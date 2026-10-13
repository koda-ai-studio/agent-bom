import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphRelationshipDetail } from "@/components/graph-relationship-detail";
import type { UnifiedEdge } from "@/lib/graph-schema";

const edge: UnifiedEdge = { id: "edge-a", source: "agent-a", target: "function-a", relationship: "uses", direction: "directed", weight: 1, traversable: false,
  first_seen: "2026-10-12T00:00:00Z", last_seen: "2026-10-12T00:01:00Z", evidence: { basis: "configured_target", source: "workflow" }, activity_id: 0 };
describe("relationship inspector", () => {
  it.each([
    { evidence: { source: "source-ast" }, title: "Configured delegation" },
    { evidence: {}, title: "Delegation (unverified)" },
    { evidence: { data_source: "runtime-proxy" }, title: "Delegated To" },
  ])("qualifies delegation as $title", ({ evidence, title }) => {
    render(<GraphRelationshipDetail edge={{ ...edge, relationship: "delegated_to", evidence }} scanId="snapshot-a" sourceLabel="Planner" targetLabel="Worker" onClose={vi.fn()} />);
    expect(screen.getByRole("heading", { name: title })).toBeVisible();
  });
  it.each([
    { relationship: "uses", sourceLabel: "Planner", targetLabel: "Invoice function", title: "Uses" },
    { relationship: "vulnerable_to", sourceLabel: "MCP server", targetLabel: "CVE-2025-29927", title: "Has CVE" },
  ])("preserves $relationship without inventing an entity type", ({ relationship, sourceLabel, targetLabel, title }) => {
    render(<GraphRelationshipDetail edge={{ ...edge, relationship }} scanId="snapshot-a" sourceLabel={sourceLabel} targetLabel={targetLabel} onClose={vi.fn()} />);
    expect(screen.getByRole("heading", { name: title })).toBeVisible();
    expect(screen.getByText(`${sourceLabel} → ${targetLabel}`)).toBeVisible();
    expect(screen.getByText(/does not establish execution/)).toBeVisible();
  });
  it("shows recorded direction, scope and evidence without promoting execution", () => {
    const close = vi.fn();
    render(<GraphRelationshipDetail edge={edge} scanId="snapshot-a" sourceLabel="Planner" targetLabel="Invoice function" onClose={close} />);
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
    render(<GraphRelationshipDetail edge={{ ...edge, first_seen: "", last_seen: "", direction: "bidirectional" }} scanId="s" sourceLabel="Planner" targetLabel="Worker" onClose={close} />);
    expect(screen.getByText("Planner ↔ Worker")).toBeVisible();
    expect(screen.getAllByText("Not recorded")).toHaveLength(2);
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
  ["vulnerable_to", "The source component is linked to a vulnerability finding. Review the recorded package and version before choosing a fix."],
])("explains %s without opening raw evidence", (relationship, explanation) => {
  render(<GraphRelationshipDetail edge={{ ...edge, relationship }} scanId="s" sourceLabel="Source" targetLabel="Target" onClose={vi.fn()} />);
  expect(screen.getByText(explanation)).toBeVisible();
  expect(screen.getByText("workflow")).toBeVisible();
  expect(screen.getByText("configured_target")).toBeVisible();
});

it("explains conservative tool impact without claiming a traced exploit", () => {
  render(<GraphRelationshipDetail edge={{ ...edge, relationship: "exploitable_via", evidence: { mapping_method: "server_scope_conservative", package: "example", version: "1.2", source: "scan" } }} scanId="s" sourceLabel="Finding" targetLabel="Tool" onClose={vi.fn()} />);
  expect(screen.getByText(/shares a server with the affected package/)).toBeVisible();
  expect(screen.getByText(/exact package-to-tool call path is not established/)).toBeVisible();
  expect(screen.getByText("example")).toBeVisible();
  expect(screen.getByText("1.2")).toBeVisible();
});

it("does not infer a source receipt from the relationship verb", () => {
  render(<GraphRelationshipDetail edge={{ ...edge, evidence: {} }} scanId="s" sourceLabel="Agent" targetLabel="Server" onClose={vi.fn()} />);
  expect(screen.getByText("Source evidence not recorded for this link.")).toBeVisible();
});

it.each(["future_relationship", "constructor"])("keeps unknown %s relationships neutral", relationship => {
  render(<GraphRelationshipDetail edge={{ ...edge, relationship, evidence: { source: { unexpected: true }, mapping_method: ["not-a-method"] } }} scanId="s" sourceLabel="A" targetLabel="B" onClose={vi.fn()} />);
  expect(screen.getByText(/Review its source evidence before drawing a security conclusion/)).toBeVisible();
  expect(screen.queryByLabelText("Recorded link evidence")).not.toBeInTheDocument();
});
