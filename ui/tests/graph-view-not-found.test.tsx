import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

let search = new URLSearchParams();
vi.mock("next/navigation", () => ({ useSearchParams: () => search }));

import NotFound from "@/app/not-found";
import { GraphViewNotFound } from "@/components/graph-view-not-found";

afterEach(cleanup);

describe("graph view not found", () => {
  it("names the unknown view and links back to the graph, keeping the scan", () => {
    search = new URLSearchParams("lens=bogus&scan=scan-7");
    render(<GraphViewNotFound />);
    expect(screen.getByRole("heading", { name: "This graph view does not exist" })).toBeInTheDocument();
    expect(screen.getByText(/lens “bogus”/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to attack paths" })).toHaveAttribute("href", "/security-graph?lens=attack-path&scan=scan-7");
    expect(screen.getByRole("link", { name: "Explore connections" })).toHaveAttribute("href", "/security-graph?lens=estate&rollup=1&scan=scan-7");
  });

  it("gives an unknown address a way back to the graph as well as to the overview", () => {
    render(<NotFound />);
    expect(screen.getByRole("link", { name: "Back to Overview" })).toHaveAttribute("href", "/");
    expect(screen.getByRole("link", { name: "Open the investigation graph" })).toHaveAttribute("href", "/security-graph?lens=attack-path");
  });
});
