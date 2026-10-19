import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphRollupRelationshipDetail } from "@/components/graph-relationship-detail";
import { mergeReciprocalRollupEdges } from "@/lib/graph-rollup-view";

describe("GraphRollupRelationshipDetail", () => {
  it("breaks a merged two-way link down by direction", () => {
    const [edge] = mergeReciprocalRollupEdges([
      { source: "env:dev", target: "env:prod", count: 2, relationships: ["uses"], directions: ["directed"], relationship_counts: { uses: 2 } },
      { source: "env:prod", target: "env:dev", count: 1, relationships: ["accessed"], directions: ["directed"], relationship_counts: { accessed: 1 } },
    ]);
    render(<GraphRollupRelationshipDetail edge={edge!} scanId="scan-1" sourceLabel="development" targetLabel="production" onClose={vi.fn()} onInspectNode={vi.fn()} />);
    expect(screen.getByText("development ↔ production")).toBeTruthy();
    expect(screen.getByText("development → production").nextElementSibling?.textContent).toBe("2");
    expect(screen.getByText("production → development").nextElementSibling?.textContent).toBe("1");
    expect(screen.queryByText("Recorded directions")).toBeNull();
  });
});
