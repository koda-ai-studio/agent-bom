import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { expandReport, isPackedReport, ReportPackingError } from "@/lib/report-packing";
import { validateScanReport } from "@/lib/validators";

type PackedDoc = {
  findings: Array<{ control_refs: string[] }>;
  packing?: { transforms: string[]; fields?: Record<string, unknown> };
  blast_radius: Array<{ finding_ref?: string }>;
  provenance?: unknown;
};

const fixture = (name: string) =>
  JSON.parse(readFileSync(join(__dirname, "fixtures", "report-schema-v2", name), "utf-8")) as Record<string, unknown>;
const packedDoc = () => fixture("packed.json") as unknown as PackedDoc;
const first = <T,>(rows: T[]): T => {
  const row = rows[0];
  if (row === undefined) throw new Error("fixture has no rows");
  return row;
};

describe("schema 2.0 report expansion", () => {
  it("expands the Python-packed golden to exactly the legacy report", () => {
    const packed = fixture("packed.json");
    expect(isPackedReport(packed)).toBe(true);
    expect(expandReport(packed)).toEqual(fixture("legacy.json"));
  });

  it("drops the schema_version the packer added when the source had none", () => {
    const packed = {
      schema_version: "2.0",
      agents: [],
      blast_radius: [],
      packing: { schema_version: "1", transforms: [] },
    };
    expect(expandReport(packed)).toEqual({ agents: [], blast_radius: [] });
  });

  it("does not modify its input and passes 1.x reports through", () => {
    const packed = fixture("packed.json");
    const before = JSON.stringify(packed);
    expandReport(packed);
    expect(JSON.stringify(packed)).toBe(before);
    const legacy = fixture("legacy.json");
    expect(expandReport(legacy)).toBe(legacy);
  });

  it.each([
    ["dangling control ref", (doc: PackedDoc) => first(doc.findings).control_refs.push("iso_27001:A.0:deadbeef")],
    ["unknown transform", (doc: PackedDoc) => doc.packing?.transforms.push("future_transform")],
    ["missing manifest", (doc: PackedDoc) => delete doc.packing],
    ["missing reference field list", (doc: PackedDoc) => delete doc.packing?.fields],
    ["dangling finding ref", (doc: PackedDoc) => (first(doc.blast_radius).finding_ref = "missing")],
    ["provenance entry type", (doc: PackedDoc) => (doc.provenance = { p: "x" })],
  ])("rejects a %s", (_label, mutate) => {
    const doc = packedDoc();
    mutate(doc);
    expect(() => expandReport(doc)).toThrow(ReportPackingError);
  });

  it("bounds reference amplification", () => {
    const doc = packedDoc();
    const finding = first(doc.findings);
    finding.control_refs = Array(20_000).fill(first(finding.control_refs));
    expect(() => expandReport(doc, 1_000_000)).toThrow(/expands beyond/);
  });

  it("imports a schema 2.0 report through the dashboard validator", () => {
    const text = readFileSync(join(__dirname, "fixtures", "report-schema-v2", "packed.json"), "utf-8");
    expect(validateScanReport(text).ok).toBe(false);
    const result = validateScanReport(text, expandReport);
    expect(result.ok).toBe(true);
    const legacy = fixture("legacy.json");
    if (result.ok) {
      const data = result.data as Record<string, unknown>;
      expect(data.agents).toEqual(legacy.agents);
      expect(data.findings).toEqual(legacy.findings);
      expect(data.schema_version).toBe("1.0");
    }
    const broken = packedDoc();
    first(broken.findings).control_refs = ["nope"];
    const rejected = validateScanReport(JSON.stringify(broken), expandReport);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.error).toMatch(/Invalid schema 2 report/);
  });
});
