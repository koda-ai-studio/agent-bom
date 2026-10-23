import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { GraphChangeExposures } from "@/components/graph-change-exposures";
import type { GraphEstateHighlightNode, GraphEstateHighlights, GraphEstatePathChange } from "@/lib/api-types";

const path = (index: number): GraphEstatePathChange => ({
  source: `agent:${index}`, target: `vuln:${index}`, hops: [`agent:${index}`, `vuln:${index}`], composite_risk: 90 - index, summary: "",
});
const control = (index: number): GraphEstateHighlightNode => ({
  kind: "node", change: "removed", id: `control:${index}`, label: `Control ${index}`, entity_type: "control",
});
const finding = (index: number): GraphEstateHighlightNode => ({
  kind: "node", change: "added", id: `finding:${index}`, label: `Finding ${index}`, entity_type: "vulnerability", severity: "critical",
});

function renderExposures(highlights: GraphEstateHighlights, extra: { onOpenDiff?: () => void; onInvestigateNode?: (id: string, label: string) => void } = {}) {
  render(<GraphChangeExposures highlights={highlights} scanId="new-scan" previousScanId="old-scan" {...extra} />);
  return screen.getByTestId("graph-changes-exposure");
}

const group = (exposure: HTMLElement, name: RegExp) => within(exposure).getByRole("group", { name });
const href = (link: HTMLElement) => new URL(link.getAttribute("href")!, "http://x");

describe("GraphChangeExposures paging", () => {
  it("pages every returned row in bounded, keyboard-reachable pages", () => {
    const exposure = renderExposures({ removed_attack_paths: { status: "complete", count: 7, top: Array.from({ length: 7 }, (_, i) => path(i)) } });
    const removed = group(exposure, /removed attack paths/i);
    expect(within(removed).getAllByRole("listitem")).toHaveLength(5);
    expect(removed).toHaveTextContent("1–5 of 7");
    const previous = within(removed).getByRole("button", { name: /previous removed attack paths/i });
    const next = within(removed).getByRole("button", { name: /next removed attack paths/i });
    expect(previous).toBeDisabled();
    expect(next.tagName).toBe("BUTTON");
    fireEvent.click(next);
    expect(within(removed).getAllByRole("listitem")).toHaveLength(2);
    expect(removed).toHaveTextContent("6–7 of 7");
    expect(removed).toHaveTextContent("agent:6 → vuln:6");
    expect(next).toBeDisabled();
    fireEvent.click(previous);
    expect(removed).toHaveTextContent("agent:0 → vuln:0");
  });

  it("shows no pager when one page holds every row", () => {
    const exposure = renderExposures({ removed_controls: { count: 2, top: [control(1), control(2)] } });
    expect(within(exposure).queryByRole("button", { name: /next/i })).toBeNull();
  });

  it("says the API returned only the top rows and opens the full paged diff for the rest", () => {
    const onOpenDiff = vi.fn();
    const exposure = renderExposures(
      { new_critical_findings: { count: 426, top: Array.from({ length: 10 }, (_, i) => finding(i)) } },
      { onOpenDiff, onInvestigateNode: vi.fn() },
    );
    const findings = group(exposure, /new critical finding nodes/i);
    expect(findings).toHaveTextContent("1–5 of top 10 by risk · 426 total");
    fireEvent.click(within(findings).getByRole("button", { name: /open the full diff for all 426 new critical finding nodes/i }));
    expect(onOpenDiff).toHaveBeenCalledTimes(1);
  });

  it("labels a lower-bound total as such", () => {
    const exposure = renderExposures(
      { new_attack_paths: { status: "lower_bound", count: 12, count_is_lower_bound: true, top: Array.from({ length: 10 }, (_, i) => path(i)) } },
      { onOpenDiff: vi.fn() },
    );
    expect(group(exposure, /new attack paths/i)).toHaveTextContent("12+ total");
  });
});

describe("GraphChangeExposures removed rows", () => {
  it("opens a removed path in the previous snapshot that held it", () => {
    const exposure = renderExposures({ removed_attack_paths: { status: "complete", count: 1, top: [path(1)] } });
    const link = within(exposure).getByRole("link", { name: "Open removed path agent:1 → vuln:1 in the previous snapshot" });
    const url = href(link);
    expect(url.pathname).toBe("/security-graph");
    expect(url.searchParams.get("scan")).toBe("old-scan");
    expect(url.searchParams.get("selected_path")).toBe("agent:1::vuln:1::agent:1->vuln:1");
  });

  it("opens a removed control focused in the previous snapshot", () => {
    const exposure = renderExposures({ removed_controls: { count: 1, top: [control(1)] } });
    const url = href(within(exposure).getByRole("link", { name: "Open removed control Control 1 in the previous snapshot" }));
    expect(url.pathname).toBe("/graph");
    expect(url.searchParams.get("scan")).toBe("old-scan");
    expect(url.searchParams.get("root")).toBe("control:1");
    expect(url.searchParams.get("investigate")).toBe("1");
  });

  it("focuses a removed control relationship on its source endpoint", () => {
    const edge: GraphEstateHighlightNode = { kind: "edge", change: "removed", id: "srv:a|policy:b|protected_by", source: "srv:a", target: "policy:b", relationship: "protected_by" };
    const exposure = renderExposures({ removed_controls: { count: 1, top: [edge] } });
    expect(exposure).toHaveTextContent("srv:a → policy:b · protected by");
    const url = href(within(exposure).getByRole("link", { name: "Open removed control srv:a → policy:b in the previous snapshot" }));
    expect(url.searchParams.get("root")).toBe("srv:a");
  });

  it("keeps removed rows as plain text when no previous snapshot is known", () => {
    render(<GraphChangeExposures highlights={{ removed_controls: { count: 1, top: [control(1)] } }} scanId="new-scan" />);
    expect(within(screen.getByTestId("graph-changes-exposure")).queryByRole("link")).toBeNull();
  });
});
