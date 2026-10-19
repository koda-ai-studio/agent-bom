import { describe, expect, it } from "vitest";

import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
import { clientQueueFocus, focusedPathEmptyState, serverPathFocus, showAnalysisBannerForEmptyQueue } from "@/lib/finding-path-focus";

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
    expect(serverPathFocus(focus)).toEqual({ nodeId: finding.node_id, findingId: finding.finding_id });
    expect(serverPathFocus({ ...focus, nodeId: "", findingId: "" })).toEqual({});
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
