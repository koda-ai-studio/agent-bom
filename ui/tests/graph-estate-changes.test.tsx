import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import type { GraphDiffResponse, GraphEstateChangesResponse } from "@/lib/api-types";
import { estateChangesHeadline, highlightPairs, mergeDriftDiffs, snapshotChangesHeadline } from "@/lib/graph-estate-changes";
import { GraphChangesEntry } from "@/components/graph-changes-entry";
import { GraphChangesPanel } from "@/components/graph-changes-panel";
import { GraphSnapshotDiff } from "@/components/graph-snapshot-diff";

const ref = (scan: string, at: string) => ({ scan_id: scan, job_id: scan, captured_at: at });
const counts = (added: number, removed: number) => ({ added, removed, changed: 0 });

function response(overrides: Partial<GraphEstateChangesResponse> = {}): GraphEstateChangesResponse {
  return {
    schema_version: "v1",
    evidence_scope: "current_estate",
    sources: [
      {
        scope_id: "aaaa", label: "aws / 123456789012", old: ref("a-1", "2026-10-01T00:00:00+00:00"), new: ref("a-2", "2026-10-08T00:00:00+00:00"),
        counts: { nodes: counts(10, 3), edges: counts(15, 5) }, total_changes: 33, nodes_by_entity_type: {}, highlights: {}, skipped_snapshots: 0,
      },
      {
        scope_id: "bbbb", label: "repo github.com/acme/app", old: ref("b-1", "2026-10-02T00:00:00+00:00"), new: ref("b-2", "2026-10-09T00:00:00+00:00"),
        counts: { nodes: counts(2, 0), edges: counts(5, 0) }, total_changes: 7, nodes_by_entity_type: {}, highlights: {}, skipped_snapshots: 1,
      },
      {
        scope_id: "cccc", label: "vercel push", old: ref("c-1", "2026-10-02T00:00:00+00:00"), new: ref("c-2", "2026-10-09T00:00:00+00:00"),
        counts: { nodes: counts(0, 0), edges: counts(0, 0) }, total_changes: 0, nodes_by_entity_type: {}, highlights: {}, skipped_snapshots: 0,
      },
    ],
    new_sources: [
      { scope_id: "dddd", label: "image nginx:1.27", new: ref("d-1", "2026-10-10T00:00:00+00:00"), reason: "first_observation", node_count: 40, edge_count: 39, skipped_snapshots: 0 },
    ],
    totals: { nodes: counts(12, 3), edges: counts(20, 5), changed_sources: 2, unchanged_sources: 1, new_sources: 1 },
    pagination: { offset: 0, limit: 50, returned: 4, total: 4, has_more: false, next_offset: null },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 4, total: 4 },
    completeness_reasons: [],
    ...overrides,
  } as GraphEstateChangesResponse;
}

describe("estateChangesHeadline", () => {
  it("summarises per-source totals and first observations", () => {
    expect(estateChangesHeadline(response())).toBe("+12 −3 nodes · +20 −5 links · 2 sources · 1 first observation");
  });

  it("says when nothing changed", () => {
    const quiet = response({
      sources: [response().sources[2]!], new_sources: [],
      totals: { nodes: counts(0, 0), edges: counts(0, 0), changed_sources: 0, unchanged_sources: 1, new_sources: 0 },
    });
    expect(estateChangesHeadline(quiet)).toBe("No changes since previous scans");
  });

  it("reports a first observation when no scope has history", () => {
    const first = response({ sources: [], totals: { nodes: counts(0, 0), edges: counts(0, 0), changed_sources: 0, unchanged_sources: 0, new_sources: 1 } });
    expect(estateChangesHeadline(first)).toBe("First observation");
  });

  it("returns null with no scan history at all", () => {
    expect(estateChangesHeadline(response({ sources: [], new_sources: [], totals: { nodes: counts(0, 0), edges: counts(0, 0), changed_sources: 0, unchanged_sources: 0, new_sources: 0 } }))).toBeNull();
  });

  it("labels a bounded page instead of implying a complete estate", () => {
    const paged = response({ pagination: { offset: 0, limit: 3, returned: 3, total: 9, has_more: true, next_offset: 3 } });
    expect(estateChangesHeadline(paged)).toMatch(/first 3 of 9 sources$/);
  });
});

describe("snapshotChangesHeadline", () => {
  const zero = { nodesAdded: 0, nodesRemoved: 0, nodesChanged: 0, edgesAdded: 0, edgesRemoved: 0, truncated: false };
  it("defers the comparison until requested", () => {
    expect(snapshotChangesHeadline(null, true)).toBe("Compare with previous snapshot");
    expect(snapshotChangesHeadline(null, false)).toBeNull();
  });
  it("reports exact counts once loaded", () => {
    expect(snapshotChangesHeadline({ ...zero, nodesAdded: 4, edgesRemoved: 2 }, true)).toBe("+4 −0 nodes · +0 −2 links");
    expect(snapshotChangesHeadline(zero, true)).toBe("No changes since previous snapshot");
  });
});

describe("highlightPairs + mergeDriftDiffs", () => {
  it("only fetches changed sources and caps the number", () => {
    expect(highlightPairs(response())).toEqual([{ oldScanId: "a-1", newScanId: "a-2" }, { oldScanId: "b-1", newScanId: "b-2" }]);
    expect(highlightPairs(response(), 1)).toHaveLength(1);
  });

  it("merges change indexes so the drift lens sees every source", () => {
    const a = {
      nodes_added: [{ id: "n1" }], nodes_removed: [], nodes_changed: ["n2"], edges_added: [["n1", "n2", "uses"]], edges_removed: [],
      change_kind_index: { nodes: { n1: "new", n2: "changed" }, edges: { "n1|n2|uses": "new" } },
      summary: { totals: { nodes: counts(1, 0), edges: counts(1, 0) } },
    } as unknown as GraphDiffResponse;
    const b = {
      nodes_added: [], nodes_removed: [{ id: "m1" }], nodes_changed: [], edges_added: [], edges_removed: [], truncated: true,
      change_kind_index: { nodes: { m1: "removed" }, edges: {} },
      summary: { totals: { nodes: counts(0, 1), edges: counts(0, 0) } },
    } as unknown as GraphDiffResponse;
    const merged = mergeDriftDiffs([a, b]);
    expect(merged.change_kind_index?.nodes).toEqual({ n1: "new", n2: "changed", m1: "removed" });
    expect(merged.nodes_removed.map(node => node.id)).toEqual(["m1"]);
    expect(merged.summary?.totals.nodes).toEqual({ added: 1, removed: 1, changed: 0 });
    expect(merged.truncated).toBe(true);
  });
});

describe("GraphChangesEntry", () => {
  it("renders the headline and opens the panel", () => {
    const onOpen = vi.fn();
    render(<GraphChangesEntry headline="+1 −0 nodes · +0 −0 links · 1 source" loading={false} error={null} highlighting={false} onOpen={onOpen} onClearHighlight={() => {}} />);
    const button = screen.getByRole("button", { name: /changed since previous scans/i });
    expect(button).toHaveTextContent("+1 −0 nodes");
    fireEvent.click(button);
    expect(onOpen).toHaveBeenCalled();
  });

  it("shows loading and unavailable states without blocking", () => {
    const { rerender } = render(<GraphChangesEntry headline={null} loading error={null} highlighting={false} onOpen={() => {}} onClearHighlight={() => {}} />);
    expect(screen.getByTestId("graph-changes-entry")).toHaveTextContent("Checking changes");
    rerender(<GraphChangesEntry headline={null} loading={false} error="boom" highlighting={false} onOpen={() => {}} onClearHighlight={() => {}} />);
    expect(screen.getByTestId("graph-changes-entry")).toHaveTextContent("Changes unavailable");
  });

  it("offers a clear action while highlighting", () => {
    const onClear = vi.fn();
    render(<GraphChangesEntry headline="x" loading={false} error={null} highlighting onOpen={() => {}} onClearHighlight={onClear} />);
    fireEvent.click(screen.getByRole("button", { name: /clear highlight/i }));
    expect(onClear).toHaveBeenCalled();
  });
});

describe("GraphChangesPanel", () => {
  it("lists each source with counts, separates first observations, and wires actions", () => {
    const onHighlight = vi.fn();
    const onOpenDiff = vi.fn();
    render(
      <GraphChangesPanel open changes={response()} loading={false} error={null} highlighting={false} highlightLoading={false}
        selectedPair={null} onClose={() => {}} onHighlight={onHighlight} onOpenDiff={onOpenDiff} diffDetails={null} />,
    );
    const rows = screen.getAllByTestId("graph-changes-source");
    expect(rows).toHaveLength(3);
    expect(within(rows[0]!).getByText("aws / 123456789012")).toBeInTheDocument();
    expect(rows[0]).toHaveTextContent("+10 −3 nodes");
    expect(rows[0]).toHaveTextContent("+15 −5 links");
    expect(rows[1]).toHaveTextContent("1 snapshot without graph skipped");
    expect(rows[2]).toHaveTextContent("No changes");
    const first = screen.getByTestId("graph-changes-first-observation");
    expect(first).toHaveTextContent("image nginx:1.27");
    expect(first).toHaveTextContent("40 nodes");
    expect(first).toHaveTextContent("First observation");
    fireEvent.click(screen.getByRole("button", { name: "Highlight changes" }));
    expect(onHighlight).toHaveBeenCalled();
    fireEvent.click(within(rows[0]!).getByRole("button", { name: /open diff/i }));
    expect(onOpenDiff).toHaveBeenCalledWith({ oldScanId: "a-1", newScanId: "a-2" }, "aws / 123456789012");
    expect(within(rows[2]!).queryByRole("button", { name: /open diff/i })).toBeNull();
  });

  it("discloses partial pages and skipped evidence", () => {
    render(
      <GraphChangesPanel open loading={false} error={null} highlighting={false} highlightLoading={false} selectedPair={null}
        changes={response({
          pagination: { offset: 0, limit: 3, returned: 3, total: 9, has_more: true, next_offset: 3 },
          completeness_reasons: ["previous_graph_unavailable"],
        })}
        onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />,
    );
    expect(screen.getByTestId("graph-changes-completeness")).toHaveTextContent("Showing 3 of 9 sources");
    expect(screen.getByTestId("graph-changes-completeness")).toHaveTextContent("Some earlier snapshots have no graph");
  });

  it("disables highlight when nothing changed", () => {
    render(
      <GraphChangesPanel open loading={false} error={null} highlighting={false} highlightLoading={false} selectedPair={null}
        changes={response({ sources: [response().sources[2]!], totals: { nodes: counts(0, 0), edges: counts(0, 0), changed_sources: 0, unchanged_sources: 1, new_sources: 1 } })}
        onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />,
    );
    expect(screen.getByRole("button", { name: "Highlight changes" })).toBeDisabled();
  });
});

describe("GraphSnapshotDiff", () => {
  it("shows exact counts and only the non-empty change lists", () => {
    const diff = { nodes_added: [{ id: "n1", label: "requests" }], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [] } as unknown as GraphDiffResponse;
    render(<GraphSnapshotDiff diff={diff} loading={false} error={null}
      counts={{ nodesAdded: 1, nodesRemoved: 0, nodesChanged: 0, edgesAdded: 2, edgesRemoved: 0, truncated: true }} />);
    const view = screen.getByTestId("graph-snapshot-diff");
    expect(view).toHaveTextContent("+1 −0 nodes · 0 changed · +2 −0 links");
    expect(view).toHaveTextContent("Lists show the first changes only");
    expect(within(view).getByText("Added")).toBeInTheDocument();
    expect(within(view).queryByText("Removed")).toBeNull();
  });
});
