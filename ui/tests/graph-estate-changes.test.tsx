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

describe("GraphChangesPanel exposures", () => {
  const baselineSource = {
    scope_id: "eeee", label: "local-agents", old: { scan_id: "showcase-baseline", job_id: "", captured_at: "2026-10-10T02:00:00+00:00" },
    new: ref("showcase", "2026-10-17T02:00:00+00:00"), baseline: "snapshot_continuity" as const,
    counts: { nodes: counts(2727, 15), edges: counts(14371, 4) }, total_changes: 17129, nodes_by_entity_type: {}, skipped_snapshots: 0,
    highlights: {
      new_critical_findings: { count: 426, top: [
        { kind: "node" as const, change: "added" as const, id: "misconfig:a", label: "SSH open to the internet", severity: "critical", entity_type: "misconfiguration" },
      ] },
      removed_controls: { count: 1, top: [{ kind: "node" as const, change: "removed" as const, id: "control:mfa", label: "MFA policy", entity_type: "control" }] },
      new_attack_paths: { status: "complete", count: 3, top: [{ source: "agent:x", target: "vuln:y", hops: ["agent:x", "server:z", "vuln:y"], composite_risk: 82.5, summary: "Agent reaches critical CVE" }] },
      removed_attack_paths: { status: "complete", count: 1, top: [{ source: "agent:x", target: "vuln:old", hops: ["agent:x", "vuln:old"], composite_risk: 40, summary: "" }] },
    },
  };
  const changes = response({ sources: [baselineSource], new_sources: [], completeness_reasons: ["snapshot_baseline"],
    totals: { nodes: counts(2727, 15), edges: counts(14371, 4), changed_sources: 1, unchanged_sources: 0, new_sources: 0 } });

  it("names the comparable baseline instead of reporting a first observation", () => {
    render(<GraphChangesPanel open changes={changes} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />);
    expect(screen.queryByTestId("graph-changes-first-observation")).toBeNull();
    const row = screen.getByTestId("graph-changes-source");
    expect(row).toHaveTextContent("Compared with earlier snapshot showcase-baseline");
    expect(screen.getByTestId("graph-changes-completeness")).toHaveTextContent("scanned once");
    expect(screen.getByRole("button", { name: "Highlight changes" })).toBeEnabled();
    // The basis is explicit so these numbers are never read as finding counts.
    expect(screen.getByText(/Counts are graph nodes and links between the two snapshots, not finding occurrences/)).toBeInTheDocument();
  });

  it("lists new and removed exposure and drills into it", () => {
    const onInvestigateNode = vi.fn();
    render(<GraphChangesPanel open changes={changes} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null}
      onInvestigateNode={onInvestigateNode} />);
    const exposure = screen.getByTestId("graph-changes-exposure");
    expect(exposure).toHaveTextContent("New critical finding nodes · 426");
    expect(exposure).toHaveTextContent("New attack paths · 3");
    expect(exposure).toHaveTextContent("Removed attack paths · 1");
    expect(exposure).toHaveTextContent("Removed controls · 1");
    fireEvent.click(within(exposure).getByRole("button", { name: /investigate SSH open to the internet/i }));
    expect(onInvestigateNode).toHaveBeenCalledWith("misconfig:a", "SSH open to the internet");
    // A new path opens the path queue with that exact path selected, in the snapshot that recorded it.
    const link = within(exposure).getByRole("link", { name: /investigate path agent:x → vuln:y/i });
    const href = new URL(link.getAttribute("href")!, "http://x");
    expect(href.pathname).toBe("/security-graph");
    expect(href.searchParams.get("scan")).toBe("showcase");
    expect(href.searchParams.get("node")).toBe("agent:x");
    expect(href.searchParams.get("selected_path")).toBe("agent:x::vuln:y::agent:x->server:z->vuln:y");
    expect(href.searchParams.get("path_view")).toBe("path");
    expect(within(exposure).queryByRole("link", { name: /investigate path agent:x → vuln:old/i })).toBeNull();
  });

  it("states the trend's issue counts for the same two scans beside the graph-node counts", () => {
    const issueChange = { basis: "issue_groups", old: { critical: 291, high: 710, medium: 0, low: 0, total: 1701 }, new: { critical: 332, high: 817, medium: 0, low: 0, total: 1969 } };
    const paired = response({ ...changes, sources: [{ ...baselineSource, issue_change: issueChange }] });
    render(<GraphChangesPanel open changes={paired} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />);
    const line = screen.getByTestId("graph-changes-issue-basis");
    expect(line).toHaveTextContent("Open issues, the posture trend's unit: critical 291 → 332 (+41) · high 710 → 817 (+107)");
  });

  it("omits the issue line when the trend recorded neither scan", () => {
    render(<GraphChangesPanel open changes={changes} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />);
    expect(screen.queryByTestId("graph-changes-issue-basis")).toBeNull();
  });

  it("names path and reach endpoints by display name with the raw id as a tooltip", () => {
    const named = response({ ...changes, sources: [{ ...baselineSource, highlights: {
      new_attack_paths: { status: "complete", count: 1, top: [{ source: "user:bob", target: "cloud:bastion", source_label: "bob@contractor", target_label: "prod-bastion (EC2)", hops: ["user:bob", "cloud:bastion"], composite_risk: 100, summary: "" }] },
      new_credential_reach: { count: 1, top: [{ kind: "edge" as const, change: "added" as const, id: "srv|cred|exposes_cred", source: "srv:billing", target: "cred:k", source_label: "Billing server", target_label: "Stripe key", relationship: "exposes_cred" }] },
    } }] });
    render(<GraphChangesPanel open changes={named} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />);
    const exposure = screen.getByTestId("graph-changes-exposure");
    expect(exposure).toHaveTextContent("bob@contractor → prod-bastion (EC2) · 1 hop");
    expect(exposure).toHaveTextContent("Billing server → Stripe key");
    expect(exposure).not.toHaveTextContent("user:bob");
    expect(within(exposure).getByText("bob@contractor")).toHaveAttribute("title", "user:bob");
    expect(within(exposure).getByText("prod-bastion (EC2)")).toHaveAttribute("title", "cloud:bastion");
    expect(within(exposure).getByText("Stripe key")).toHaveAttribute("title", "cred:k");
    expect(within(exposure).getByRole("link", { name: "Investigate path bob@contractor → prod-bastion (EC2)" })).toBeInTheDocument();
  });

  it("falls back to the raw id when the API names no endpoint", () => {
    render(<GraphChangesPanel open changes={changes} loading={false} error={null} highlighting={false} highlightLoading={false}
      selectedPair={null} onClose={() => {}} onHighlight={() => {}} onOpenDiff={() => {}} diffDetails={null} />);
    expect(screen.getByTestId("graph-changes-exposure")).toHaveTextContent("agent:x → vuln:y");
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

  it("pages long lists, links every entry to its asset in the right snapshot, and keeps long ids inside the drawer", () => {
    const added = Array.from({ length: 60 }, (_, index) => ({ id: `arn:aws:ec2:us-east-1:210987654321:instance/i-${index}`, label: `resource: arn:aws:ec2:us-east-1:210987654321:instance/i-${index}` }));
    const removed = [{ id: "pkg:old", label: "old-package" }];
    const diff = { nodes_added: added, nodes_removed: removed, nodes_changed: [], edges_added: [], edges_removed: [] } as unknown as GraphDiffResponse;
    render(<GraphSnapshotDiff diff={diff} loading={false} error={null} pair={{ oldScanId: "base", newScanId: "head" }}
      counts={{ nodesAdded: 1129, nodesRemoved: 1, nodesChanged: 0, edgesAdded: 0, edgesRemoved: 0, truncated: true }} />);
    const addedList = screen.getByRole("list", { name: "Added nodes" });
    expect(within(addedList).getAllByRole("link")).toHaveLength(10);
    const first = within(addedList).getAllByRole("link")[0]!;
    expect(first).toHaveAttribute("title", added[0]!.label);
    expect(first.className).toContain("truncate");
    // The distinguishing tail of a long id stays visible.
    expect(first.textContent).toMatch(/…/);
    expect(first.textContent!.endsWith("210987654321:instance/i-0")).toBe(true);
    const href = new URL(first.getAttribute("href")!, "http://x");
    expect(href.pathname).toBe("/graph");
    expect(href.searchParams.get("root")).toBe(added[0]!.id);
    expect(href.searchParams.get("scan")).toBe("head");
    expect(screen.getByText("1–10 of 60 listed · 1,129 added")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next added nodes" }));
    expect(within(addedList).getAllByRole("link")[0]).toHaveAttribute("title", added[10]!.label);
    expect(screen.getByText("11–20 of 60 listed · 1,129 added")).toBeInTheDocument();
    const removedLink = within(screen.getByRole("list", { name: "Removed nodes" })).getByRole("link");
    expect(new URL(removedLink.getAttribute("href")!, "http://x").searchParams.get("scan")).toBe("base");
    expect(screen.getByTestId("graph-snapshot-diff").querySelector(".grid")!.className).toContain("min-w-0");
  });
});
