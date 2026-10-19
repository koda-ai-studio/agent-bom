import { describe, expect, it } from "vitest";

import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { clientQueueFocus, focusedPathEmptyState, serverPathFocus, showAnalysisBannerForEmptyQueue, sourceSnapshotFallback } from "@/lib/finding-path-focus";

const finding = {
  id: "CVE-2023-36258",
  finding_id: "16530e6c-ddaf-5651-ac6c-396b32d92af8",
  finding_node_id: "vuln:demo-estate:16530e6c-ddaf-5651-ac6c-396b32d92af8",
  node_id: "package:pypi:langchain@0.0.150:dce85e7272e8",
  entity_type: "package",
  scan_id: "showcase",
  packages: ["langchain"],
  agents: [],
};

describe("finding investigation link", () => {
  it("opens the current estate and keeps the finding's source scan only as provenance", () => {
    const params = new URL(buildFindingInvestigationHref(finding), "http://localhost").searchParams;
    expect(params.has("scan")).toBe(false);
    expect(params.get("finding_scan")).toBe("showcase");
    expect(params.get("node")).toBe(finding.node_id);
    expect(params.get("finding")).toBe(finding.finding_id);
  });

  it("pins a snapshot only when the caller is browsing that snapshot", () => {
    const params = new URL(buildFindingInvestigationHref(finding, { scanId: "scan-selected" }), "http://localhost").searchParams;
    expect(params.get("scan")).toBe("scan-selected");
    expect(params.get("finding_scan")).toBe("showcase");
  });
});

describe("server path focus", () => {
  const focus = { scanId: "", cve: "CVE-2023-36258", packageName: "", agentName: "", nodeId: finding.node_id, findingId: finding.finding_id, traceId: "" };

  it("asks the server for the occurrence instead of filtering one loaded page", () => {
    expect(serverPathFocus(focus)).toEqual({ nodeId: finding.node_id, findingId: finding.finding_id, advisoryId: "CVE-2023-36258" });
    expect(serverPathFocus({ ...focus, nodeId: "", findingId: "" })).toEqual({});
  });

  it("sends the advisory only with the occurrence's own node, never as a free-standing widening", () => {
    expect(serverPathFocus({ ...focus, nodeId: "" })).toEqual({ findingId: finding.finding_id });
    expect(serverPathFocus({ ...focus, cve: "" })).toEqual({ nodeId: finding.node_id, findingId: finding.finding_id });
  });

  it("does not re-filter a server-focused page with the alias the link carried", () => {
    expect(clientQueueFocus(focus, true)).toEqual({});
    expect(clientQueueFocus({ ...focus, nodeId: "", findingId: "" }, false)).toMatchObject({ cve: "CVE-2023-36258" });
  });
});

describe("empty focused queue", () => {
  it("never pairs a green complete banner with an empty focused result", () => {
    expect(showAnalysisBannerForEmptyQueue({ status: "complete" })).toBe(false);
    expect(showAnalysisBannerForEmptyQueue({ status: "limited" })).toBe(true);
    expect(showAnalysisBannerForEmptyQueue(undefined)).toBe(false);
  });

  it("explains a confirmed miss and offers the package neighbourhood", () => {
    const state = focusedPathEmptyState({ serverFocused: true, coversAllMatches: true, cve: "CVE-2023-36258", currentEstate: true });
    expect(state?.title).toBe("No attack path reaches this finding in the current estate");
    expect(state?.detail).toMatch(/neighbourhood/);
  });

  it("does not claim absence when the focused read was bounded", () => {
    const state = focusedPathEmptyState({ serverFocused: true, coversAllMatches: false, cve: "", currentEstate: false });
    expect(state?.title).toBe("No matching path in the searched part of the queue");
    expect(state?.detail).toMatch(/not proof/);
  });

  it("leaves unfocused empty states to the page", () => {
    expect(focusedPathEmptyState({ serverFocused: false, coversAllMatches: true, cve: "", currentEstate: true })).toBeNull();
  });
});

describe("source snapshot fallback", () => {
  const miss = { node_id: "pkg:x", finding_id: "f", resolved_from: null, covers_all_matches: true };

  it("retries the finding's own snapshot when the current estate has no path for it", () => {
    expect(sourceSnapshotFallback({ selectedScanId: "current-estate:abc", findingScanId: "showcase", focus: miss, matches: 0 })).toBe("showcase");
  });

  it("stays put when paths were found, the read was bounded, or the snapshot is already the source", () => {
    expect(sourceSnapshotFallback({ selectedScanId: "current-estate:abc", findingScanId: "showcase", focus: miss, matches: 1 })).toBeNull();
    expect(sourceSnapshotFallback({ selectedScanId: "current-estate:abc", findingScanId: "showcase", focus: { ...miss, covers_all_matches: false }, matches: 0 })).toBeNull();
    expect(sourceSnapshotFallback({ selectedScanId: "showcase", findingScanId: "showcase", focus: miss, matches: 0 })).toBeNull();
    expect(sourceSnapshotFallback({ selectedScanId: "current-estate:abc", findingScanId: "", focus: miss, matches: 0 })).toBeNull();
    expect(sourceSnapshotFallback({ selectedScanId: "current-estate:abc", findingScanId: "showcase", focus: null, matches: 0 })).toBeNull();
  });
});
