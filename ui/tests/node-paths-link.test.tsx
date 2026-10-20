import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NodePathsLink } from "@/components/node-paths-link";

const getGraphAttackPaths = vi.fn();
vi.mock("@/lib/api", () => ({ api: { getGraphAttackPaths: (...args: unknown[]) => getGraphAttackPaths(...args) } }));

describe("NodePathsLink", () => {
  beforeEach(() => getGraphAttackPaths.mockReset());

  it("opens every ranked path through the node, counted, so a chain beyond depth 1 is one click away", async () => {
    getGraphAttackPaths.mockResolvedValue({ pagination: { total: 4 }, focus: { covers_all_matches: true } });
    render(<NodePathsLink scanId="scan-1" nodeId="snowflake:storage_integration:I" />);
    const link = await screen.findByRole("link", { name: "4 attack paths through this node" });
    const href = new URL(link.getAttribute("href")!, "http://x");
    expect(href.pathname).toBe("/security-graph");
    expect(href.searchParams.get("node")).toBe("snowflake:storage_integration:I");
    expect(href.searchParams.get("scan")).toBe("scan-1");
    expect(getGraphAttackPaths).toHaveBeenCalledWith({ scanId: "scan-1", nodeId: "snowflake:storage_integration:I", limit: 1 });
  });

  it("marks a lower bound when the search did not cover every path", async () => {
    getGraphAttackPaths.mockResolvedValue({ pagination: { total: 1 }, focus: { covers_all_matches: false } });
    render(<NodePathsLink scanId="scan-1" nodeId="n" />);
    expect(await screen.findByRole("link", { name: "1+ attack path through this node" })).toBeInTheDocument();
  });

  it("renders nothing when no path crosses the node", async () => {
    getGraphAttackPaths.mockResolvedValue({ pagination: { total: 0 }, focus: { covers_all_matches: true } });
    const { container } = render(<NodePathsLink scanId="scan-1" nodeId="n" />);
    await vi.waitFor(() => expect(getGraphAttackPaths).toHaveBeenCalled());
    expect(container.querySelector("a")).toBeNull();
  });
});
