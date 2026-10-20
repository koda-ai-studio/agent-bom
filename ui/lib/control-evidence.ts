/** A compliance control's evidence is its mapped finding set; links carry that set, never one sample asset. */
export function controlGraphHref(input: { frameworkId: string; control: string; scanId?: string | undefined }): string {
  const params = new URLSearchParams({ lens: "attack-path", framework: input.frameworkId, control: input.control });
  if (input.scanId) params.set("scan", input.scanId);
  return `/security-graph?${params}`;
}

const REPORT_SLUGS: Record<string, string> = { iso27001: "iso-27001", "nist-ai-rmf": "nist" };

/** Framework ids on the compliance page differ from the signed report's public slugs for two frameworks. */
export function controlReportSlug(frameworkId: string): string {
  return REPORT_SLUGS[frameworkId] ?? frameworkId;
}

export interface ComplianceReportBundle {
  framework?: string;
  generated_at?: string;
  expires_at?: string;
  nonce?: string;
  signature?: string;
  signature_algorithm?: string;
  controls?: Array<{ control_id?: string } & Record<string, unknown>>;
}

/**
 * One control's slice of the signed framework bundle. The HMAC signs the whole
 * bundle, so the excerpt carries the signature and nonce as a reference for
 * verification against the full bundle, not as a signature of the excerpt.
 */
export function controlEvidenceExcerpt(bundle: ComplianceReportBundle, controlCode: string) {
  const control = bundle.controls?.find((entry) => entry.control_id === controlCode);
  if (!control) throw new Error(`${controlCode} is not in the signed bundle for ${bundle.framework ?? "this framework"}`);
  return {
    schema_version: "control-evidence-excerpt.v1",
    excerpt_of: {
      framework: bundle.framework,
      generated_at: bundle.generated_at,
      expires_at: bundle.expires_at,
      nonce: bundle.nonce,
      signature: bundle.signature,
      signature_algorithm: bundle.signature_algorithm,
      note: "The signature covers the full framework bundle; verify against that bundle.",
    },
    control,
  };
}

/** The `<framework>:<control>` tag a finding carries for this control, exactly as stamped. */
export function controlTagFor(tags: readonly string[] | null | undefined, control: string): string | null {
  return (tags ?? []).find((tag) => tag.slice(tag.lastIndexOf(":") + 1) === control) ?? null;
}

/** Why a control-filtered path supports the control: the finding it ends on carries the control's tag. */
export function pathSupportReason(
  path: { vuln_ids?: readonly string[] | undefined; finding_ids?: readonly string[] | undefined; target?: string | undefined },
  control: string,
  tag: string | null,
): string {
  const advisory = path.vuln_ids?.[0];
  const subject = advisory ? advisory : `finding ${path.finding_ids?.[0] ?? path.target ?? "on this path"}`;
  return tag ? `Ends on ${subject}, which carries ${tag}` : `Ends on ${subject}, which is mapped to ${control}`;
}

const ACRONYMS = new Set(["mcp", "s3", "iam", "vm", "gke", "eks", "aks", "rds", "sql", "api", "ai", "llm"]);

/** `mcp_server` → `MCP server`: the recorded asset type, readable. */
export function assetTypeLabel(value: string | null | undefined): string | null {
  const words = (value ?? "").trim().split(/[_\s-]+/).filter(Boolean);
  if (!words.length) return null;
  const label = words.map((word) => (ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word.toLowerCase())).join(" ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}
