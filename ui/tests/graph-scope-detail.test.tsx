import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphScopeDetail } from "@/components/graph-scope-detail";
import type { GraphRollupContainer } from "@/lib/api-types";

const item: GraphRollupContainer = {
  id: "account:prod", label: "Production account", entity_type: "cloud_account",
  severity: "critical", is_container: true, has_children: true, direct_child_count: 2,
  aggregate: { descendant_count: 42, by_type: { server: 2, package: 40 }, severity_counts: { critical: 1, none: 41 }, worst_severity: "critical", worst_severity_rank: 5, internet_exposed: true, toxic_combo: false, exposed_count: 3, toxic_count: 0 },
};

describe("scope inspector", () => {
  it("separates contained counts, direct children, severity, and recorded exposure", () => {
    const open = vi.fn();
    render(<GraphScopeDetail item={item} docked scanId="scan-a" onClose={vi.fn()} onOpenScope={open} />);
    expect(screen.getByRole("complementary", { name: "Scope details" })).toHaveTextContent("Cloud account · scope");
    expect(screen.getByText("42")).toBeVisible();
    expect(screen.getByRole("region", { name: "Scope composition" })).toHaveTextContent("Package40Server2");
    expect(screen.getByRole("region", { name: "Recorded severity" })).toHaveTextContent("No severity 41");
    expect(screen.getByText("3 entities recorded as internet exposed.")).toBeVisible();
    expect(screen.queryByText(/blast radius/i)).not.toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Explore scope" }));
    expect(open).toHaveBeenCalledOnce();
  });
  it("supports closing the docked scope with Escape", () => {
    const close = vi.fn();
    render(<GraphScopeDetail item={item} docked onClose={close} />);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalledOnce();
  });
});
