/**
 * A finding's mapped compliance controls, deduped and grouped by framework,
 * each linked to the compliance page section that evaluates it.
 */

/** Tag framework key → compliance page section id and label. */
const FRAMEWORKS: Record<string, { pageId: string; label: string; codePrefix?: string }> = {
  owasp_llm: { pageId: "owasp-llm", label: "OWASP LLM Top 10" },
  owasp_mcp: { pageId: "owasp-mcp", label: "OWASP MCP Top 10" },
  owasp_agentic: { pageId: "owasp-agentic", label: "OWASP Agentic Top 10" },
  atlas: { pageId: "atlas", label: "MITRE ATLAS" },
  mitre_atlas: { pageId: "atlas", label: "MITRE ATLAS" },
  nist_ai_rmf: { pageId: "nist-ai-rmf", label: "NIST AI RMF" },
  eu_ai_act: { pageId: "eu-ai-act", label: "EU AI Act" },
  nist_csf: { pageId: "nist-csf", label: "NIST CSF 2.0" },
  iso_27001: { pageId: "iso27001", label: "ISO 27001" },
  soc2: { pageId: "soc2", label: "SOC 2" },
  cis: { pageId: "cis", label: "CIS Controls v8" },
  cmmc: { pageId: "cmmc", label: "CMMC 2.0" },
  nist_800_53: { pageId: "nist-800-53", label: "NIST SP 800-53" },
  pci_dss: { pageId: "pci-dss", label: "PCI DSS 4.0" },
  fedramp: { pageId: "fedramp", label: "FedRAMP Moderate", codePrefix: "FedRAMP-" },
};
const ORDER = Object.keys(FRAMEWORKS);
const OTHER = "Other mappings";

export interface FindingControlGroup {
  framework: string;
  label: string;
  controls: { code: string; href: string | null }[];
}

function normalizeFramework(value: string): string {
  return value.trim().toLowerCase().replace(/-/g, "_");
}

export function groupFindingControls(
  tags: readonly string[] | undefined,
  controls?: readonly Record<string, unknown>[] | undefined,
): FindingControlGroup[] {
  const pairs: [string, string][] = [];
  for (const tag of tags ?? []) {
    const [framework, ...rest] = tag.split(":");
    const control = rest.join(":").trim();
    if (framework && control) pairs.push([normalizeFramework(framework), control]);
  }
  for (const control of controls ?? []) {
    const framework = typeof control.framework === "string" ? control.framework : "generic";
    const code = [control.control, control.control_id, control.id].find((value): value is string => typeof value === "string" && Boolean(value.trim()));
    if (code) pairs.push([normalizeFramework(framework), code.trim()]);
  }
  // A legacy generic tag repeats a control some named framework already claims.
  const named = new Set(pairs.filter(([framework]) => framework !== "generic").map(([, control]) => control));
  const groups = new Map<string, FindingControlGroup>();
  const seen = new Set<string>();
  for (const [framework, raw] of pairs) {
    if (framework === "generic" && named.has(raw)) continue;
    const known = FRAMEWORKS[framework];
    const code = known?.codePrefix && raw.startsWith(known.codePrefix) ? raw.slice(known.codePrefix.length) : raw;
    const groupKey = known ? known.pageId : OTHER;
    if (seen.has(`${groupKey}:${code}`)) continue;
    seen.add(`${groupKey}:${code}`);
    const group = groups.get(groupKey) ?? { framework: known ? framework : "other", label: known?.label ?? OTHER, controls: [] };
    group.controls.push({
      code,
      href: known ? `/compliance?${new URLSearchParams({ framework: known.pageId, control: code })}` : null,
    });
    groups.set(groupKey, group);
  }
  const rank = (group: FindingControlGroup) => (group.label === OTHER ? ORDER.length : ORDER.indexOf(group.framework));
  return [...groups.values()]
    .map((group) => ({ ...group, controls: group.controls.sort((a, b) => a.code.localeCompare(b.code, undefined, { numeric: true })) }))
    .sort((a, b) => rank(a) - rank(b));
}

/** Compliance evidence scoped to what the compliance search can match: the package, else the agent. */
export function complianceEvidenceHref(
  vuln: { packages: readonly string[]; agents: readonly string[] },
  scanId?: string | undefined,
): string {
  const packageName = vuln.packages.find((name) => name && name !== "asset")?.replace(/@[^@]*$/, "");
  const subject = packageName || vuln.agents.find(Boolean);
  const params = new URLSearchParams();
  if (subject) params.set("q", subject);
  if (scanId) params.set("scan", scanId);
  const query = params.toString();
  return query ? `/compliance?${query}` : "/compliance";
}
