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
    expect(screen.getByText(/configured_target/)).toBeVisible();
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
