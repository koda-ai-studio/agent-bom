import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CorrelatedAssetPath, incidentAssetRoot } from "@/components/correlated-asset-path";

const path = ["github:repository:team/app", "aws:role:app-prod", "kubernetes:workload:prod/app", "mcp:tool:analytics/query", "snowflake:table:prod/private/data"];

describe("correlated asset investigation", () => {
  it("uses only the primary correlation's finding when its asset belongs to that path", () => {
    expect(incidentAssetRoot(path, "primary", [
      { correlation_id: "other", asset_id: path[0]! },
      { correlation_id: "primary", asset_id: "aws:role:unrelated" },
      { correlation_id: "primary", asset_id: path[1]! },
    ])).toBe(path[1]);
    expect(incidentAssetRoot(path, "primary", [])).toBe(path[0]);
    expect(incidentAssetRoot([], "primary", [])).toBeNull();
  });

  it("keeps the exact node and snapshot in links and reveals the remaining sequence", () => {
    render(<CorrelatedAssetPath assets={path} scanId="showcase" />);
    expect(screen.getAllByRole("listitem")).toHaveLength(4);
    const link = screen.getByRole("link", { name: /Inspect app-prod/ });
    const url = new URL(link.getAttribute("href")!, "https://example.invalid");
    expect(url.searchParams.get("scan")).toBe("showcase");
    expect(url.searchParams.get("root")).toBe(path[1]);
    expect(url.searchParams.get("investigate")).toBe("1");
    expect(screen.getByText(path[1]!)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Show all 5 assets/ }));
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
    expect(screen.getByText(/does not establish permissions or exploitation/)).toBeInTheDocument();
  });

  it("does not link unpinned assets when the showcase is unavailable", () => {
    render(<CorrelatedAssetPath assets={path} scanId={null} />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
