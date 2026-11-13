import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

let search = new URLSearchParams();
let pathname = "/security-graph";
vi.mock("next/navigation", () => ({ useSearchParams: () => search, usePathname: () => pathname }));

import { GraphViewNotFound } from "@/components/graph-view-not-found";
import { RouteNotFound } from "@/components/route-not-found";

afterEach(cleanup);

describe("graph view not found", () => {
  it("names the unknown view and links back to the graph, keeping the scan", () => {
    search = new URLSearchParams("lens=bogus&scan=scan-7");
    render(<GraphViewNotFound />);
    expect(screen.getByRole("heading", { name: "This graph view does not exist" })).toBeInTheDocument();
    expect(screen.getByText(/view “bogus”/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to attack paths" })).toHaveAttribute("href", "/security-graph?lens=attack-path&scan=scan-7");
    expect(screen.getByRole("link", { name: "Explore connections" })).toHaveAttribute("href", "/security-graph?lens=estate&rollup=1&scan=scan-7");
  });

  it("gives an unknown address under the graph routes the graph's way back, and others the overview", () => {
    search = new URLSearchParams();
    pathname = "/graph/nope";
    render(<RouteNotFound />);
    expect(screen.getByText(/page \/graph\/nope/)).toBeInTheDocument();
    cleanup();
    pathname = "/nowhere";
    render(<RouteNotFound />);
    expect(screen.getByRole("link", { name: "Back to Overview" })).toHaveAttribute("href", "/");
  });
});
