import { describe, expect, it } from "vitest";
import type { GraphIncidentPage } from "@/lib/api-types";
import { buildGraphInvestigationBundle } from "@/lib/graph-investigation-bundle";

function page(overrides: Partial<GraphIncidentPage> = {}): GraphIncidentPage {
  return { scan_id: "scan/+ ?", snapshot_generation: "generation-1", node_id: "pkg:/+ ?", found: true,
    direction: "both", limit: 24, node: { id: "pkg:/+ ?", entity_type: "package", data_sources: ["lockfile"], attributes: {} },
    nodes: [{ id: "vuln:one", entity_type: "vulnerability", data_sources: ["osv"], attributes: {} }],
    edges: [{ id: "receipt", source: "pkg:/+ ?", target: "vuln:one", relationship: "vulnerable_to", evidence: { basis: "advisory", source_id: "receipt-1" } }],
    next_cursor: null, completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: null, scope: "incident_edge_page", missing_endpoint_count: 0 },
    ...overrides } as GraphIncidentPage;
}
const make = (pages: GraphIncidentPage[], url = "https://control.example/graph?token=secret#secret") => buildGraphInvestigationBundle("scan/+ ?", "pkg:/+ ?", pages, url);
describe("portable graph investigation", () => {
  it("retains exact identities, source receipts and an allowlisted return link", () => {
    const bundle = make([page()], "https://control.example/graph?token=secret&finding=occurrence%2B1&finding_scan=earlier#secret");
    expect(bundle.selection).toMatchObject({ scan_id: "scan/+ ?", snapshot_generation: "generation-1", node_id: "pkg:/+ ?", finding_node_ids: ["vuln:one"], finding_context: { finding_id: "occurrence+1", scan_id: "earlier" } });
    const url = new URL(bundle.return_url);
    expect(url.searchParams.get("root")).toBe("pkg:/+ ?");
    expect(url.searchParams.get("scan")).toBe("scan/+ ?");
    expect(url.searchParams.get("finding_scan")).toBe("earlier");
    expect(bundle.return_url).not.toContain("secret");
    expect(bundle.relationships[0]!.evidence).toEqual({ basis: "advisory", source_id: "receipt-1" });
    expect(bundle.sources).toEqual(["lockfile", "osv"]);
    expect(bundle.scope.collection_coverage).toBe("unknown");
  });
  it("keeps missing endpoints and incomplete page receipts without exporting cursor tokens", () => {
    const bundle = make([page({ nodes: [], next_cursor: "private-cursor" })]);
    expect(bundle.scope).toMatchObject({ more_relationships_available: true, missing_endpoint_ids: ["vuln:one"] });
    expect(bundle.relationships).toHaveLength(1);
    expect(bundle.page_receipts[0]!.has_more).toBe(true);
    expect(JSON.stringify(bundle)).not.toContain("private-cursor");
  });
  it("deduplicates replayed pages without inventing source coverage", () => {
    const bundle = make([page(), page()]);
    expect(bundle.relationships).toHaveLength(1);
    expect(bundle.nodes).toHaveLength(2);
    expect(bundle.scope).toMatchObject({ pages: 2, collection_coverage: "unknown" });
    expect(bundle.limitations.join(" ")).toContain("unsigned");
  });
  it.each([{ scan_id: "other" }, { node_id: "other" }, { snapshot_generation: "other" }, { found: false }, { direction: "in" }] as Partial<GraphIncidentPage>[])("rejects mismatched evidence %j", mismatch => {
    expect(() => make([page(), page(mismatch)])).toThrow("Load consistent");
  });
  it("rejects an unavailable or unversioned read", () => {
    expect(() => make([])).toThrow();
    expect(() => make([page({ snapshot_generation: null })])).toThrow();
  });
});

it("exports the resolved estate and canonical node while preserving the requested selection", () => {
  const resolved = page({ scan_id: "current-estate:new", node_id: "canonical", resolved_from: "old-id", node: { ...page().node!, id: "canonical" } });
  const bundle = buildGraphInvestigationBundle("current-estate:old", "old-id", [resolved, { ...resolved, resolved_from: null }], "https://control.example/graph");
  expect(bundle.selection).toMatchObject({ scan_id: "current-estate:new", node_id: "canonical", requested_scan_id: "current-estate:old", requested_node_id: "old-id" });
  expect(bundle.page_receipts[0]?.resolved_from).toBe("old-id");
  expect(new URL(bundle.return_url).searchParams.get("root")).toBe("canonical");
  expect(new URL(bundle.return_url).searchParams.get("scan")).toBe("current-estate:new");
});

it("never treats a partial terminal page as complete evidence", () => {
  const partial = page({ completeness: { ...page().completeness, status: "truncated", complete: false, truncated: true, reason: "budget" } });
  expect(make([partial]).scope).toMatchObject({ recorded_relationships_complete: false, collection_coverage: "unknown" });
});

it("does not claim complete relationships when endpoint records are absent", () => {
  const bundle = make([page({ nodes: [] })]);
  expect(bundle.scope.recorded_relationships_complete).toBe(false);
  expect(bundle.scope.missing_endpoint_ids).toEqual(["vuln:one"]);
});

it("treats an absent completeness receipt as unknown instead of crashing", () => {
  const missing = page();
  delete (missing as Partial<GraphIncidentPage>).completeness;
  expect(make([missing]).scope.recorded_relationships_complete).toBe(false);
  expect(make([missing, page()]).scope.recorded_relationships_complete).toBe(false);
});
