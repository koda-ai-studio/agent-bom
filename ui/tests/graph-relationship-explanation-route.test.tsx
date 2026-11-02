import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphRelationshipExplanation } from "@/components/graph-relationship-explanation";

describe("declared agent-graph routes", () => {
  it("shows the branch, route role and declaring call of a source-declared delegation", () => {
    render(<GraphRelationshipExplanation edge={{ relationship: "delegated_to", evidence: {
      source: "source-ast", evidence: "StateGraph.add_conditional_edges", branch: "needs_research", kind: "entry",
      provenance: "declared", file_path: "app.py", line_number: 50,
    } }} />);
    const rows = screen.getByLabelText("Recorded link evidence");
    expect(rows).toHaveTextContent(/Declared by\s*StateGraph\.add_conditional_edges/);
    expect(rows).toHaveTextContent(/Branch\s*needs_research/);
    expect(rows).toHaveTextContent(/Route role\s*Entry point/);
    expect(rows).toHaveTextContent(/Declared at\s*app\.py:50/);
  });

  it("leaves unrelated links unchanged", () => {
    render(<GraphRelationshipExplanation edge={{ relationship: "depends_on", evidence: { source: "workflow" } }} />);
    const rows = screen.getByLabelText("Recorded link evidence");
    expect(rows).not.toHaveTextContent("Route role");
    expect(rows).not.toHaveTextContent("Declared at");
  });
});
