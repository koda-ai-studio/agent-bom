import type { LineageNodeData } from "@/components/lineage-nodes";

/** Recorded finding context; recommendations are proposals, never verification. */
export function GraphFindingContext({ data }: { data: LineageNodeData }) {
  if (!["vulnerability", "misconfiguration"].includes(data.nodeType)) return null;
  const attrs = data.attributes ?? {};
  const text = (...keys: string[]) => keys.map(key => attrs[key]).find(value => typeof value === "string" && value.trim()) as string | undefined;
  const path = text("file_path", "path");
  const line = attrs.start_line ?? attrs.line ?? attrs.line_number;
  const location = path ? `${path}${typeof line === "number" && Number.isInteger(line) && line > 0 ? `:${line}` : ""}` : "Source location not recorded";
  const recommendation = text("recommendation", "remediation");
  const fixedVersion = data.fixedVersion || text("fixed_version");
  const severity = data.severity?.toLowerCase();
  const factors = [
    severity && ["critical", "high", "medium", "low"].includes(severity) ? `${severity[0]!.toUpperCase()}${severity.slice(1)} severity` : null,
    data.isKev === true ? "Known exploited advisory (KEV)" : null,
  ].filter(Boolean);
  return <section aria-label="Finding investigation" className="space-y-3 rounded-lg border border-outline p-3 text-xs text-ink-secondary [overflow-wrap:anywhere]">
    <div><h4 className="font-semibold text-foreground">Why investigate</h4><p className="mt-1">{factors.join(" · ") || "Priority factors not recorded"}</p><p className="mt-1">Inspect affected assets and relationship receipts below to assess scope. A severity rating does not establish exploitability.</p></div>
    <div><h4 className="font-semibold text-foreground">Source location</h4><p className="mt-1">{location}</p></div>
    <div><h4 className="font-semibold text-foreground">Remediation</h4><p className="mt-1">{recommendation || (fixedVersion ? `Recorded fixed version: ${fixedVersion}` : "Remediation not recorded")}</p>
      {(recommendation || fixedVersion) && <p className="mt-1">Recorded guidance, not a verified fix. Review applicability, rescan after changes and compare snapshots.</p>}
    </div>
  </section>;
}
