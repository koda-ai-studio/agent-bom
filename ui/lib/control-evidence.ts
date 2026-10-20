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
