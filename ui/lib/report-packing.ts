/**
 * Expand a schema 2.0 agent-bom JSON report to the 1.0 shape the dashboard reads.
 *
 * Mirrors `agent_bom.output.report_packing.expand_report`: schema 2.0 writes each
 * shared record once and references it by ID; `packing.transforms` lists the
 * rewrites. Unknown transforms, dangling references and documents that would
 * expand past `maxExpandedBytes` are rejected, because imports are untrusted.
 */

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

const PACKING_SCHEMA_VERSION = "1";
const PROVENANCE_KEYS = ["discovery_provenance", "version_provenance", "package_discovery_provenance", "package_version_provenance"];
const PROVENANCE_REF_KEYS = new Map(PROVENANCE_KEYS.map((key) => [`${key}_ref`, key]));
const MAX_PROVENANCE_DEPTH = 8;
const MAX_REF_LENGTH = 512;
export const DEFAULT_MAX_EXPANDED_BYTES = 100 * 1024 * 1024;

const TRANSFORMS = [
  "provenance_refs",
  "root_packages_alias",
  "inventory_snapshot_packages",
  "blast_radius_finding_refs",
  "asset_refs",
  "package_refs",
  "compliance_control_refs",
] as const;

const MAX_REF_FIELDS = 256;

export class ReportPackingError extends Error {}

/** `packing.fields[refKey]`: `name`, or `name=source_name` when the referenced record names the field differently. */
function refFields(manifest: JsonObject, refKey: string): Map<string, string> {
  const declared = isObject(manifest.fields) ? manifest.fields[refKey] : undefined;
  if (!Array.isArray(declared) || declared.length > MAX_REF_FIELDS) {
    throw new ReportPackingError(`packing.fields.${refKey} must be a list of field names`);
  }
  const keys = new Map<string, string>();
  for (const item of declared) {
    if (typeof item !== "string" || !item || item.length > MAX_REF_LENGTH) {
      throw new ReportPackingError(`packing.fields.${refKey} must be a list of field names`);
    }
    const [row, source] = item.split("=", 2) as [string, string | undefined];
    keys.set(row, source || row);
  }
  return keys;
}

const isObject = (value: unknown): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export function isPackedReport(doc: unknown): boolean {
  return isObject(doc) && typeof doc.schema_version === "string" && doc.schema_version.split(".")[0] === "2";
}

class Budget {
  used = 0;
  private sizes = new WeakMap<object, number>();
  constructor(private readonly limit: number) {}
  charge(value: Json): void {
    const size =
      typeof value === "object" && value !== null
        ? (this.sizes.get(value) ?? this.measure(value))
        : JSON.stringify(value).length;
    this.used += size;
    if (this.used > this.limit) throw new ReportPackingError(`report expands beyond ${this.limit} bytes`);
  }
  private measure(value: object): number {
    const size = JSON.stringify(value).length;
    this.sizes.set(value, size);
    return size;
  }
}

const copy = (value: Json): Json => (value === null || typeof value !== "object" ? value : structuredClone(value));

function ref(value: Json | undefined, field: string): string {
  if (typeof value !== "string" || !value || value.length > MAX_REF_LENGTH) {
    throw new ReportPackingError(`${field} must be a non-empty ID string`);
  }
  return value;
}

function table(value: Json | undefined, name: string): Map<string, JsonObject> {
  if (value === undefined) return new Map();
  if (!isObject(value)) throw new ReportPackingError(`${name} must be an object of records`);
  const rows = new Map<string, JsonObject>();
  for (const [key, row] of Object.entries(value)) {
    if (!isObject(row)) throw new ReportPackingError(`${name} must map IDs to objects`);
    rows.set(key, row);
  }
  return rows;
}

function restoreProvenance(value: Json, records: Map<string, JsonObject>, budget: Budget, depth: number): Json {
  if (Array.isArray(value)) return value.map((child) => restoreProvenance(child, records, budget, depth));
  if (!isObject(value)) return value;
  const out: JsonObject = {};
  for (const [key, child] of Object.entries(value)) {
    const original = PROVENANCE_REF_KEYS.get(key);
    if (original !== undefined && !(original in value)) {
      const record = records.get(ref(child, key));
      if (!record) throw new ReportPackingError(`${key} names an unknown provenance record`);
      if (depth >= MAX_PROVENANCE_DEPTH) throw new ReportPackingError("provenance records nest too deeply");
      budget.charge(record);
      out[original] = restoreProvenance(record, records, budget, depth + 1);
    } else {
      out[key] = restoreProvenance(child, records, budget, depth);
    }
  }
  return out;
}

function uniqueIndex(rows: Json | undefined, key: string): Map<string, JsonObject> {
  const index = new Map<string, JsonObject>();
  const duplicate = new Set<string>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (isObject(row) && typeof row[key] === "string") {
      const id = row[key] as string;
      if (index.has(id)) duplicate.add(id);
      index.set(id, row);
    }
  }
  duplicate.forEach((id) => index.delete(id));
  return index;
}

function restore(row: JsonObject, source: JsonObject, keys: Map<string, string>, refKey: string, budget: Budget): JsonObject {
  const out: JsonObject = {};
  keys.forEach((sourceKey, rowKey) => {
    if (!(rowKey in row) && sourceKey in source) {
      const value = source[sourceKey] as Json;
      budget.charge(value);
      out[rowKey] = copy(value);
    }
  });
  for (const [key, value] of Object.entries(row)) if (key !== refKey) out[key] = value;
  return out;
}

function expandRows(rows: Json | undefined, index: Map<string, JsonObject>, keys: Map<string, string>, refKey: string, budget: Budget): void {
  if (!Array.isArray(rows)) return;
  rows.forEach((row, position) => {
    if (!isObject(row) || !(refKey in row)) return;
    const source = index.get(ref(row[refKey], refKey));
    if (!source) throw new ReportPackingError(`${refKey} names an unknown record`);
    rows[position] = restore(row, source, keys, refKey, budget);
  });
}

function serverPackageLists(doc: JsonObject): Json[][] {
  const lists: Json[][] = [];
  for (const agent of Array.isArray(doc.agents) ? doc.agents : []) {
    if (!isObject(agent) || !Array.isArray(agent.mcp_servers)) continue;
    for (const server of agent.mcp_servers) if (isObject(server) && Array.isArray(server.packages)) lists.push(server.packages);
  }
  return lists;
}

function expandControls(doc: JsonObject, controls: Map<string, JsonObject>, budget: Budget): void {
  if (!Array.isArray(doc.findings)) return;
  doc.findings = doc.findings.map((finding) => {
    if (!isObject(finding) || !("control_refs" in finding)) return finding;
    const refs = finding.control_refs;
    if (!Array.isArray(refs)) throw new ReportPackingError("control_refs must be a list of control IDs");
    const out: JsonObject = {};
    for (const [key, value] of Object.entries(finding)) {
      if (key !== "control_refs") {
        out[key] = value;
        continue;
      }
      out.controls = refs.map((id) => {
        const control = controls.get(ref(id, "control_refs"));
        if (!control) throw new ReportPackingError("control_refs names an unknown compliance control");
        budget.charge(control);
        return { ...control };
      });
    }
    return out;
  });
}

function expandAssets(doc: JsonObject, keys: Map<string, string>, budget: Budget): void {
  const index = uniqueIndex(doc.assets, "stable_id");
  for (const finding of Array.isArray(doc.findings) ? doc.findings : []) {
    if (!isObject(finding) || !isObject(finding.asset) || !("asset_ref" in finding.asset)) continue;
    const source = index.get(ref(finding.asset.asset_ref, "asset_ref"));
    if (!source) throw new ReportPackingError("asset_ref names an unknown asset");
    finding.asset = restore(finding.asset, source, keys, "asset_ref", budget);
  }
}

function insertAfter(doc: JsonObject, anchor: string, key: string, value: Json): JsonObject {
  const out: JsonObject = {};
  for (const [name, child] of Object.entries(doc)) {
    out[name] = child;
    if (name === anchor) out[key] = value;
  }
  if (!(key in out)) out[key] = value;
  return out;
}

function expandInventoryPackages(doc: JsonObject, budget: Budget): void {
  const snapshot = doc.inventory_snapshot;
  if (!isObject(snapshot)) return;
  if (!Array.isArray(snapshot.agents)) throw new ReportPackingError("inventory_snapshot.agents must be a list");
  const flat: Json[] = [];
  for (const agent of snapshot.agents) {
    for (const server of isObject(agent) && Array.isArray(agent.mcp_servers) ? agent.mcp_servers : []) {
      if (isObject(server) && Array.isArray(server.packages)) flat.push(...server.packages);
    }
  }
  flat.forEach((pkg) => budget.charge(pkg));
  doc.inventory_snapshot = insertAfter(snapshot, "generated_at", "packages", flat.map(copy));
}

/** Return the 1.0 form of a report; any other value is returned unchanged. */
export function expandReport(doc: unknown, maxExpandedBytes = DEFAULT_MAX_EXPANDED_BYTES): unknown {
  if (!isPackedReport(doc)) return doc;
  const packed = doc as JsonObject;
  const manifest = packed.packing;
  if (!isObject(manifest) || manifest.schema_version !== PACKING_SCHEMA_VERSION) {
    throw new ReportPackingError("schema 2 report has no supported packing manifest");
  }
  const transforms = manifest.transforms;
  if (!Array.isArray(transforms) || !transforms.every((name) => typeof name === "string" && (TRANSFORMS as readonly string[]).includes(name))) {
    throw new ReportPackingError("schema 2 report lists an unknown packing transform");
  }
  const applied = new Set(transforms as string[]);
  const budget = new Budget(maxExpandedBytes);
  const records = applied.has("provenance_refs") ? table(packed.provenance, "provenance") : new Map<string, JsonObject>();
  let report = (applied.has("provenance_refs") ? restoreProvenance(packed, records, budget, 0) : structuredClone(packed)) as JsonObject;
  delete report.provenance;
  const controls = applied.has("compliance_control_refs") ? table(report.compliance_controls, "compliance_controls") : new Map();
  if (applied.has("compliance_control_refs")) delete report.compliance_controls;

  if (applied.has("compliance_control_refs")) expandControls(report, controls, budget);
  if (applied.has("package_refs")) {
    const entities = isObject(report.ai_bom_entities) ? report.ai_bom_entities.packages : undefined;
    const index = uniqueIndex(entities, "id");
    const keys = refFields(manifest, "package_ref");
    for (const rows of serverPackageLists(report)) expandRows(rows, index, keys, "package_ref", budget);
  }
  if (applied.has("asset_refs")) expandAssets(report, refFields(manifest, "asset_ref"), budget);
  if (applied.has("blast_radius_finding_refs")) {
    const keys = refFields(manifest, "finding_ref");
    expandRows(report.blast_radius, uniqueIndex(report.findings, "canonical_id"), keys, "finding_ref", budget);
  }
  if (applied.has("inventory_snapshot_packages")) expandInventoryPackages(report, budget);
  if (applied.has("root_packages_alias")) {
    const packages = isObject(report.ai_bom_entities) ? report.ai_bom_entities.packages : undefined;
    if (!Array.isArray(packages)) throw new ReportPackingError("ai_bom_entities.packages is required to restore root packages");
    budget.charge(packages);
    report = insertAfter(report, "ai_bom_entities", "packages", packages.map(copy));
  }
  const legacy = typeof manifest.legacy_schema_version === "string" && manifest.legacy_schema_version.startsWith("1")
    ? manifest.legacy_schema_version
    : "1.0";
  if ("schema_version" in report) report.schema_version = legacy;
  if ("spec_version" in report) report.spec_version = legacy;
  delete report.packing;
  return report;
}
