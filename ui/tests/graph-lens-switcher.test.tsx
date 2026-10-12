import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { GraphLensSwitcher, buildInvestigationLensHref } from "@/components/graph-lens-switcher";

const push = vi.fn();
let pathname = "/security-graph";
let params = new URLSearchParams();
vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push }),
  useSearchParams: () => params,
}));

describe("Investigation navigation", () => {
  beforeEach(() => { pathname = "/security-graph"; params = new URLSearchParams(); push.mockClear(); });

  it("offers two tasks without duplicate graph destinations or a second legend", () => {
    render(<GraphLensSwitcher />);
    expect(screen.getAllByRole("button").map(button => button.textContent)).toEqual(["Find a path", "Explore connections"]);
    expect(screen.getByRole("button", { name: "Find a path" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByText("Legend")).not.toBeInTheDocument();
    expect(screen.queryByText("More views")).not.toBeInTheDocument();
  });

  it.each(["lineage", "mesh", "context", "cloud", "repository", "identity", "estate", "asset-drift"])("keeps legacy %s links in Explore connections", lens => {
    params = new URLSearchParams({ lens });
    render(<GraphLensSwitcher />);
    expect(screen.getByRole("button", { name: "Explore connections" })).toHaveAttribute("aria-current", "page");
    fireEvent.click(screen.getByRole("button", { name: "Explore connections" }));
    expect(push).not.toHaveBeenCalled();
  });

  it("preserves snapshot, finding, focus and scenario when opening connections", () => {
    params = new URLSearchParams({ scan: "scan-123", finding: "finding-1", node: "asset-1", root: "agent:payments", root_label: "Payments", scenario: "scenario-1", state: "proposed", unrelated: "drop-me" });
    render(<GraphLensSwitcher />);
    fireEvent.click(screen.getByRole("button", { name: "Explore connections" }));
    const href = new URL(push.mock.calls[0]![0], "http://fixture");
    expect(Object.fromEntries(href.searchParams)).toEqual({ scan: "scan-123", finding: "finding-1", node: "asset-1", root: "agent:payments", root_label: "Payments", scenario: "scenario-1", state: "proposed", lens: "estate", rollup: "1", finding_scan: "scan-123" });
  });

  it("opens paths with the selected snapshot and removes graph composition state", () => {
    params = new URLSearchParams({ scan: "old-snapshot", lens: "context", rollup: "1", rollup_node: "old-group", trace: "trace-1" });
    render(<GraphLensSwitcher scanId="selected-snapshot" />);
    fireEvent.click(screen.getByRole("button", { name: "Find a path" }));
    expect(push).toHaveBeenCalledWith("/security-graph?scan=selected-snapshot&trace=trace-1&lens=attack-path");
  });

  it("recognizes the legacy graph route as connections", () => {
    pathname = "/graph";
    render(<GraphLensSwitcher />);
    expect(screen.getByRole("button", { name: "Explore connections" })).toHaveAttribute("aria-current", "page");
  });

  it("retains exact contextual identifiers when building a scoped deep link", () => {
    const context = new URLSearchParams({ scan: "s/1", agent: "a", cve: "CVE-1", package: "pkg", root: "a:1", q: "Agent 1", investigate: "1", rollup: "1", scope: "old" });
    expect(Object.fromEntries(new URL(buildInvestigationLensHref("/security-graph?lens=identity&scope=identity", context), "http://fixture").searchParams)).toEqual({ scan: "s/1", agent: "a", cve: "CVE-1", package: "pkg", root: "a:1", q: "Agent 1", investigate: "1", lens: "identity", scope: "identity" });
  });
});
